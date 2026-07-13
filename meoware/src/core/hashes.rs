/**
 * Hash Constants - Seeded DJB2 + XOR finalization
 * Algorithm: seed=0x4E67C6A7, body=((h<<5)+h)+c, xor=0x2B8E4F91
 * */

pub const HASH_SEED: u32 = 0x4E67C6A7;
pub const HASH_XOR: u32 = 0x2B8E4F91;

/* Module hashes */
pub const NTDLL_HASH: u32 = 0x59ac125e;
pub const KERNEL32_HASH: u32 = 0xab506c86;

/* ntdll - Nt* syscalls */
pub const NTOPENPROCESS_HASH: u32 = 0x8088b60b;

/* kernel32 functions */
pub const CREATEPROCESSW_HASH: u32 = 0x603dac20;