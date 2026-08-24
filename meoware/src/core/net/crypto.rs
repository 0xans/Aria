use core::arch::x86_64::*;

pub struct Aes256 {
    round_keys: [__m128i; 15]
}

impl Aes256 {
    unsafe fn new(key: &[u8; 32]) -> Self {
        let mut rk = [_mm_setzero_si128(); 15];

        let mut k0 = _mm_loadu_si128(key.as_ptr() as *const __m128i);
        let mut k1 = _mm_loadu_si128(key.as_ptr().add(16) as *const __m128i);
        rk[0] = k0;
        rk[1] = k1;

        macro_rules! expand_even {
            ($rcon:expr, $idx:expr) => {{
                let t = _mm_aeskeygenassist_si128(k1, $rcon);
                let t = _mm_shuffle_epi32(t, 0xFF);
                let mut tmp = _mm_slli_si128(k0, 4);
                k0 = _mm_xor_si128(k0, tmp);
                tmp = _mm_slli_si128(k0, 4);
                k0 = _mm_xor_si128(k0, tmp);
                tmp = _mm_slli_si128(k0, 4);
                k0 = _mm_xor_si128(k0, tmp);
                k0 = _mm_xor_si128(k0, t);
                rk[$idx] = k0;
            }};
        }

        macro_rules! expand_odd {
            ($idx:expr) => {{
                let t = _mm_aeskeygenassist_si128(k0, 0);
                let t = _mm_shuffle_epi32(t, 0xAA);
                let mut tmp = _mm_slli_si128(k1, 4);
                k1 = _mm_xor_si128(k1, tmp);
                tmp = _mm_slli_si128(k1, 4);
                k1 = _mm_xor_si128(k1, tmp);
                tmp = _mm_slli_si128(k1, 4);
                k1 = _mm_xor_si128(k1, tmp);
                k1 = _mm_xor_si128(k1, t);
                rk[$idx] = k1;
            }};
        }
        expand_even!(0x01, 2);  
        expand_odd!(3);
        expand_even!(0x02, 4);  
        expand_odd!(5);
        expand_even!(0x04, 6);  
        expand_odd!(7);
        expand_even!(0x08, 8);  
        expand_odd!(9);
        expand_even!(0x10, 10); 
        expand_odd!(11);
        expand_even!(0x20, 12); 
        expand_odd!(13);
        expand_even!(0x40, 14);
        Aes256 { round_keys: rk }
    }

    unsafe fn encrypt_block(&self, block: __m128i) -> __m128i {
        let mut state = _mm_xor_si128(block, self.round_keys[0]);
        state = _mm_aesenc_si128(state, self.round_keys[1]);
        state = _mm_aesenc_si128(state, self.round_keys[2]);
        state = _mm_aesenc_si128(state, self.round_keys[3]);
        state = _mm_aesenc_si128(state, self.round_keys[4]);
        state = _mm_aesenc_si128(state, self.round_keys[5]);
        state = _mm_aesenc_si128(state, self.round_keys[6]);
        state = _mm_aesenc_si128(state, self.round_keys[7]);
        state = _mm_aesenc_si128(state, self.round_keys[8]);
        state = _mm_aesenc_si128(state, self.round_keys[9]);
        state = _mm_aesenc_si128(state, self.round_keys[10]);
        state = _mm_aesenc_si128(state, self.round_keys[11]);
        state = _mm_aesenc_si128(state, self.round_keys[12]);
        state = _mm_aesenc_si128(state, self.round_keys[13]);
        _mm_aesenclast_si128(state, self.round_keys[14])
    }

    unsafe fn encrypt_block_bytes(&self, input: &[u8; 16]) -> [u8; 16] {
        let block = _mm_loadu_si128(input.as_ptr() as *const __m128i);
        let enc = self.encrypt_block(block);
        let mut out = [0u8; 16];
        _mm_storeu_si128(out.as_mut_ptr() as *mut __m128i, enc);
        out
    }
}

#[derive(Clone, Copy)]
struct GfBlock {
    hi: u64,
    lo: u64,
}

impl GfBlock {
    fn zero() -> Self {
        GfBlock { hi: 0, lo: 0 }
    }

    fn from_be_bytes(bytes: &[u8; 16]) -> Self {
        GfBlock {
            hi: u64::from_be_bytes([bytes[0], bytes[1],  bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7]]),
            lo: u64::from_be_bytes([bytes[8], bytes[9],  bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]])
        }
    }

    fn to_be_bytes(&self) -> [u8; 16] {
        let mut out = [0u8; 16];
        out[..8].copy_from_slice(&self.hi.to_be_bytes());
        out[8..].copy_from_slice(&self.lo.to_be_bytes());
        out
    }

    fn xor(self, other: Self) -> Self {
        GfBlock {
            hi: self.hi ^ other.hi,
            lo: self.lo ^ other.lo,
        }
    }

    fn gf_mul(self, other: Self) -> Self {
        let mut z = GfBlock::zero();
        let mut v = other;

        // Process hi bits (GCM bits 0..63 of self)
        for i in 0..64 {
            if (self.hi >> (63 - i)) & 1 == 1 {
                z = z.xor(v);
            }
            // Shift v right by 1 this means the bit 127 falls off
            let carry = v.lo & 1;
            v.lo = (v.lo >> 1) | ((v.hi & 1) << 63);
            v.hi >>= 1;
            if carry == 1 {
                v.hi ^= 0xE100000000000000u64;
            } 
        }

        // Process lo bits (GCM bits 64..127 of self)
        for i in 0..64 {
            if (self.lo >> (63 - i)) & 1 == 1 {
                z = z.xor(v);
            }
            let carry = v.lo & 1;
            v.lo = (v.lo >> 1) | ((v.lo & 1) << 63);
            v.lo >>= 1;
            if carry == 1 {
                v.lo ^= 0xE100000000000000u64;
            } 
        }

        z
    }
}

struct Ghash {
    h: GfBlock,
    state: GfBlock,
}

impl Ghash {
    fn new(h: GfBlock) -> Self {
        Ghash { h, state: GfBlock::zero() }
    }

    fn update_block(&mut self, block: &[u8; 16]) {
        let x = GfBlock::from_be_bytes(block);
        self.state = self.state.xor(x).gf_mul(self.h)
    }

    fn update(&mut self, data: &[u8]) {
        let mut chunks = data.chunks_exact(16);
        for chunk in &mut chunks {
            let mut block = [0u8; 16];
            block.copy_from_slice(chunk);
            self.update_block(&block)
        }
        let remainder = chunks.remainder();
        if !remainder.is_empty() {
            let mut block = [0u8; 16];
            block[..remainder.len()].copy_from_slice(remainder);
            self.update_block(&block);
        }
    }

    fn finalize(mut self, aad_len: usize, ct_len: usize) -> [u8; 16] {
        let mut len_block = [0u8; 16];
        len_block[..8].copy_from_slice(&((aad_len as u64 * 8).to_be_bytes()));
        len_block[8..].copy_from_slice(&((ct_len as u64 * 8).to_be_bytes()));
        self.update_block(&len_block);
        self.state.to_be_bytes()
    }
}


fn inc32(counter: &mut [u8; 16]) {
    let ctr = u32::from_be_bytes([counter[12], counter[13], counter[14], counter[15]]);
    let new_ctr = ctr.wrapping_add(1);
    counter[12..16].copy_from_slice(&new_ctr.to_be_bytes());
}

pub fn aes256_gcm_encrypt(key: &[u8; 32], plaintext: &[u8]) -> Vec<u8> {
    unsafe { aes256_gcm_encrypt_inner(key, plaintext) }
}

unsafe fn aes256_gcm_encrypt_inner(key: &[u8; 32], plaintext: &[u8]) -> Vec<u8> {
    let cipher = Aes256::new(key);

    // Generate 12 bytes nonce from RDTSC
    let mut nonce = [0u8; 12];
    {
        let seed: u64;
        core::arch::asm!(
            "rdtsc", 
            "shl rdx, 32",
            "or rax, rdx",
            out("rax") seed,
            out("rdx") _,
        );

        let mut state = seed;
        for b in nonce.iter_mut() {
            state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            *b = (state >> 33) as u8;
        }
    }

    // Build inital counter blcok: [nonce][0x00000001]
    let mut j0 = [0u8; 16];
    j0[..12].copy_from_slice(&nonce);
    j0[15] = 1;

    // Compute H = AES(K, 0^128) for GHASH
    let h_bytes = cipher.encrypt_block_bytes(&[0u8; 16]);
    let h = GfBlock::from_be_bytes(&h_bytes);

    // CTR encryption start at counter = J0 + 1
    let mut counter = j0;
    inc32(&mut counter);

    let mut ciphertext = vec![0u8; plaintext.len()];
    let mut ghash = Ghash::new(h);

    // Encrypt full 16 byte block
    let full_block = plaintext.len() / 16;
    for i in 0..full_block {
        let keystream = cipher.encrypt_block_bytes(&counter);
        inc32(&mut counter);

        let offset = i * 16;
        for j in 0..16 {
            ciphertext[offset + j] = plaintext[offset + j] ^ keystream[j];
        }
    }

    // GHASH over ciphertext
    ghash.update(&ciphertext);
    let ghash_result = ghash.finalize(0, ciphertext.len());

    // Tag = GHASH_result XOR AES(K, J0)
    let j0_enc = cipher.encrypt_block_bytes(&j0);
    let mut tag = [0u8; 16];
    for i in 0..16 {
        tag[i] = ghash_result[i] ^ j0_enc[i];
    }

    // Wire format: [nonce(12bytes)][ciphertext][tag(16bytes)]
    let mut result = Vec::with_capacity(12 + ciphertext.len() + 16);
    result.extend_from_slice(&nonce);
    result.extend_from_slice(&ciphertext);
    result.extend_from_slice(&tag);
    result
}