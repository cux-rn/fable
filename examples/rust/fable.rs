// Fable v0.5 — single-file Rust example (no dependencies): Fable-P, Fable-AEAD (both parameter sets), Fable-Hash-256.
// Research draft, NOT for production. Self-test against test_vectors_v0.3.json values.
// Build/run: rustc -O fable.rs -o fable && ./fable

const RC: [u32; 12] = [
    0xb17217f7, 0x193ea7aa, 0x9c041f7e, 0xf2272ae3, 0x65dc76ef, 0x90a08566,
    0xd54d783f, 0xf1c6c0c0, 0x22afbfba, 0x5e071979, 0x6f19c912, 0x9c651dc7,
];
const IV0: u32 = 0x4661626C;
const IV1_HASH: u32 = 0x01202000;

/// Parameter set: `Fable` = P_12/P_8 (default), `FableF` = P_12/P_6.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Set { Fable, FableF }
impl Set {
    fn light_rounds(self) -> usize { if self == Set::FableF { 6 } else { 8 } }
    fn iv1(self) -> u32 { if self == Set::FableF { 0x012020C6 } else { 0x012020C8 } }
}

#[inline(always)]
fn q(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    s[a] = s[a].wrapping_add(s[b]); s[d] = (s[d] ^ s[a]).rotate_left(16);
    s[c] = s[c].wrapping_add(s[d]); s[b] = (s[b] ^ s[c]).rotate_left(12);
    s[a] = s[a].wrapping_add(s[b]); s[d] = (s[d] ^ s[a]).rotate_left(8);
    s[c] = s[c].wrapping_add(s[d]); s[b] = (s[b] ^ s[c]).rotate_left(7);
}

/// `rounds` rounds of Fable-P using the LAST `rounds` constants (P_8 -> RC[4..11], P_6 -> RC[6..11]).
pub fn permute(s: &mut [u32; 16], rounds: usize) {
    for i in 12 - rounds..12 {
        s[0] ^= RC[i];
        s[5] ^= RC[i].rotate_left(16);
        q(s, 0, 4, 8, 12); q(s, 1, 5, 9, 13); q(s, 2, 6, 10, 14); q(s, 3, 7, 11, 15);
        q(s, 0, 5, 10, 15); q(s, 1, 6, 11, 12); q(s, 2, 7, 8, 13); q(s, 3, 4, 9, 14);
    }
}

fn ld32(p: &[u8]) -> u32 { u32::from_le_bytes([p[0], p[1], p[2], p[3]]) }
fn xor_rate(s: &mut [u32; 16], blk: &[u8]) { for j in 0..8 { s[j] ^= ld32(&blk[4 * j..]); } }
fn xor_rate_padded(s: &mut [u32; 16], blk: &[u8]) { // blk.len() < 32, 10* padding
    let mut buf = [0u8; 32]; buf[..blk.len()].copy_from_slice(blk); buf[blk.len()] = 0x80; xor_rate(s, &buf);
}
fn rate_bytes(s: &[u32; 16]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for j in 0..8 { out[4 * j..4 * j + 4].copy_from_slice(&s[j].to_le_bytes()); }
    out
}

struct Ctx { s: [u32; 16], k: [u32; 8], rl: usize }
impl Ctx {
    fn new(set: Set, key: &[u8; 32], nonce: &[u8; 24], ad: &[u8]) -> Ctx {
        let mut k = [0u32; 8];
        for j in 0..8 { k[j] = ld32(&key[4 * j..]); }
        let mut s = [0u32; 16];
        s[0] = IV0; s[1] = set.iv1();
        s[2..10].copy_from_slice(&k);
        for j in 0..6 { s[10 + j] = ld32(&nonce[4 * j..]); }
        permute(&mut s, 12);
        for j in 0..8 { s[8 + j] ^= k[j]; }
        let rl = set.light_rounds();
        if !ad.is_empty() {
            let full = ad.len() / 32;
            for i in 0..full { xor_rate(&mut s, &ad[32 * i..]); permute(&mut s, rl); }
            xor_rate_padded(&mut s, &ad[32 * full..]); permute(&mut s, rl);
        }
        s[15] ^= 0x8000_0000;
        Ctx { s, k, rl }
    }
    fn finalize(&mut self) -> [u8; 32] {
        for j in 0..8 { self.s[8 + j] ^= self.k[j]; }
        permute(&mut self.s, 12);
        rate_bytes(&self.s)
    }
}

/// Returns ciphertext || 32-byte tag.
pub fn encrypt(set: Set, key: &[u8; 32], nonce: &[u8; 24], ad: &[u8], m: &[u8]) -> Vec<u8> {
    let mut c = Ctx::new(set, key, nonce, ad);
    let mut out = Vec::with_capacity(m.len() + 32);
    let full = m.len() / 32;
    for i in 0..full {
        xor_rate(&mut c.s, &m[32 * i..]);
        out.extend_from_slice(&rate_bytes(&c.s));
        permute(&mut c.s, c.rl);
    }
    let last = &m[32 * full..];
    xor_rate_padded(&mut c.s, last);
    out.extend_from_slice(&rate_bytes(&c.s)[..last.len()]);
    out.extend_from_slice(&c.finalize());
    out
}

/// Returns the plaintext, or `None` on authentication failure.
pub fn decrypt(set: Set, key: &[u8; 32], nonce: &[u8; 24], ad: &[u8], ct: &[u8]) -> Option<Vec<u8>> {
    if ct.len() < 32 { return None; }
    let (body, tag) = ct.split_at(ct.len() - 32);
    let mut c = Ctx::new(set, key, nonce, ad);
    let mut pt = Vec::with_capacity(body.len());
    let full = body.len() / 32;
    for i in 0..full {
        for j in 0..8 {
            let cw = ld32(&body[32 * i + 4 * j..]);
            pt.extend_from_slice(&(c.s[j] ^ cw).to_le_bytes());
            c.s[j] = cw;
        }
        permute(&mut c.s, c.rl);
    }
    let lastc = &body[32 * full..];
    let ks = rate_bytes(&c.s);
    let lastp: Vec<u8> = lastc.iter().zip(ks.iter()).map(|(a, b)| a ^ b).collect();
    xor_rate_padded(&mut c.s, &lastp);
    let exp = c.finalize();
    let mut d = 0u8;
    for j in 0..32 { d |= exp[j] ^ tag[j]; } // constant time
    if d != 0 { return None; }
    pt.extend_from_slice(&lastp);
    Some(pt)
}

/// Fable-Hash-256 (sponge, r = c = 256, P_12 throughout).
pub fn hash256(data: &[u8]) -> [u8; 32] {
    let mut s = [0u32; 16];
    s[0] = IV0; s[1] = IV1_HASH;
    let full = data.len() / 32;
    for i in 0..full { xor_rate(&mut s, &data[32 * i..]); permute(&mut s, 12); }
    xor_rate_padded(&mut s, &data[32 * full..]); permute(&mut s, 12);
    rate_bytes(&s)
}

// ---------------- self-test ----------------
fn hex(b: &[u8]) -> String { b.iter().map(|x| format!("{:02x}", x)).collect() }
fn state_hex(s: &[u32; 16]) -> String { let mut b = Vec::new(); for w in s { b.extend_from_slice(&w.to_le_bytes()); } hex(&b) }

fn main() {
    let mut ok = true;
    let mut check = |name: &str, got: String, exp: &str| {
        let r = got == exp; ok &= r;
        println!("{:<28} {}", name, if r { "OK" } else { "FAIL" });
    };
    let mut key = [0u8; 32]; for i in 0..32 { key[i] = i as u8; }
    let mut nonce = [0u8; 24]; for i in 0..24 { nonce[i] = i as u8; }
    let m64: Vec<u8> = (0u8..64).collect();
    let mut s = [0u32; 16]; permute(&mut s, 12);
    check("permute12_zero", state_hex(&s), "987e1eab32cefb5c1476a1517c5d0c9f81d61cb4808b32b00db6745079ed44947ea9cb25720c64fe7bb9b86e3e1db2d345a9b4024a1f5849b1f77ecc6188a8fd");
    let mut s = [0u32; 16]; permute(&mut s, 8);
    check("permute8_zero", state_hex(&s), "13bf4c33b2ac964ca319d28c2e01c0732aaf9109228e083ec58861cabc663dd6a7bbce1ed69452d5975b4def6f81f40812bfceced5a62100a16f9ef2e066e302");
    let vs: [(Set, &str, &[u8], usize, &str); 6] = [
        (Set::Fable, "fable/empty", b"", 0, "13233108192c9cd5274e9e830400ff2ac75147d59c6340000659b25887752cbb"),
        (Set::Fable, "fable/block", b"header", 32, "59358977baf9ca6b482719c0299011ab2dd25d2c03f933b17a3822ff0cfdd25448f4dfc93df45855b8f92ea1282cafaf5087a4077113e4b98949ddec135aaa37"),
        (Set::Fable, "fable/two_blocks", b"", 64, "cf86c83ad9cb6e9c81c97b6cfbbe993532718b96a49a95dbc19e3d8f68aa58381b12889a7d584bdeca7ee688c8c4f65def77ff1d86ef6efed67b89909ea972a5d7fa539b06346f3a96cdead2479a89468edf935c278085e44fe3557555938bdc"),
        (Set::FableF, "fable-f/empty", b"", 0, "1a053a4f55101f93539b2d67a051343194ccf0ac5d80a751c6ab1d5339bb1641"),
        (Set::FableF, "fable-f/block", b"header", 32, "9e43775b205f324f6fd91b0511fa4a401bf73905ea86c0066a2f94f49988c9263d6d58e99c0b8d8adf3dfb8df17ec96ef186b62d0118f8915c652a5b5a1ff768"),
        (Set::FableF, "fable-f/two_blocks", b"", 64, "323a0d285c881b5b74541171c37585e4b2e2f5b6c96de7cac16f09c913a539417a84e26b33299a848b701d1b852df32d2d5ff43202442fc5fdbf2350d149b8cdedd4ae05f26b61841783aed3d55d26b286bb5b25eb413c271547eaf293f448bd"),
    ];
    for (set, name, ad, mlen, exp) in vs.iter() {
        let m = &m64[..*mlen];
        let mut ct = encrypt(*set, &key, &nonce, ad, m);
        check(name, hex(&ct), exp);
        let rt = decrypt(*set, &key, &nonce, ad, &ct).as_deref() == Some(m);
        let n = ct.len(); ct[n - 1] ^= 1;
        let tamper = decrypt(*set, &key, &nonce, ad, &ct).is_none();
        check("  decrypt/tamper", (rt && tamper).to_string(), "true");
    }
    check("hash256(abc)", hex(&hash256(b"abc")), "d0a959109d1b0729c6af6b74cc176c5cd1081cc262530530c80e3ad12566603d");
    check("hash256(empty)", hex(&hash256(b"")), "22f0a458f9baa6ba8b5ebc2f4614f2643ede4628cba8dab7bd1bcaa5089c6607");
    println!("RESULT: {}", if ok { "ALL OK" } else { "FAILURES" });
    std::process::exit(if ok { 0 } else { 1 });
}
