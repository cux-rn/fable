// Fable v0.5 — single-file C++17 example: Fable-P, Fable-AEAD (both parameter sets), Fable-Hash-256.
// Research draft, NOT for production. Self-test against test_vectors_v0.3.json values.
// Build: clang++ -O2 -std=c++17 fable_example.cpp -o fable_example && ./fable_example
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace fable {

using u8 = uint8_t; using u32 = uint32_t;
using State = std::array<u32, 16>;
using Bytes = std::vector<u8>;

constexpr std::array<u32, 12> RC = {
    0xb17217f7u, 0x193ea7aau, 0x9c041f7eu, 0xf2272ae3u, 0x65dc76efu, 0x90a08566u,
    0xd54d783fu, 0xf1c6c0c0u, 0x22afbfbau, 0x5e071979u, 0x6f19c912u, 0x9c651dc7u};
constexpr u32 IV0 = 0x4661626Cu, IV1_HASH = 0x01202000u;

enum class Set { Fable, FableF };                       // P_12/P_8 (default) and P_12/P_6
constexpr int lightRounds(Set s) { return s == Set::FableF ? 6 : 8; }
constexpr u32 iv1(Set s) { return s == Set::FableF ? 0x012020C6u : 0x012020C8u; }

inline u32 rotl(u32 x, int n) { return (x << n) | (x >> (32 - n)); }
inline void Q(u32& a, u32& b, u32& c, u32& d) {
    a += b; d ^= a; d = rotl(d, 16); c += d; b ^= c; b = rotl(b, 12);
    a += b; d ^= a; d = rotl(d, 8);  c += d; b ^= c; b = rotl(b, 7);
}
// `rounds` rounds using the last `rounds` constants (P_8 -> RC[4..11], P_6 -> RC[6..11]).
inline void permute(State& s, int rounds) {
    for (int i = 12 - rounds; i < 12; i++) {
        s[0] ^= RC[i]; s[5] ^= rotl(RC[i], 16);
        Q(s[0], s[4], s[8], s[12]);  Q(s[1], s[5], s[9], s[13]);
        Q(s[2], s[6], s[10], s[14]); Q(s[3], s[7], s[11], s[15]);
        Q(s[0], s[5], s[10], s[15]); Q(s[1], s[6], s[11], s[12]);
        Q(s[2], s[7], s[8], s[13]);  Q(s[3], s[4], s[9], s[14]);
    }
}

inline u32 ld32(const u8* p) { return p[0] | u32(p[1]) << 8 | u32(p[2]) << 16 | u32(p[3]) << 24; }
inline void st32(u8* p, u32 x) { p[0] = u8(x); p[1] = u8(x >> 8); p[2] = u8(x >> 16); p[3] = u8(x >> 24); }
inline void xorRate(State& s, const u8* blk) { for (int j = 0; j < 8; j++) s[j] ^= ld32(blk + 4 * j); }
inline void xorRatePadded(State& s, const u8* blk, size_t len) { u8 buf[32] = {0}; std::memcpy(buf, blk, len); buf[len] = 0x80; xorRate(s, buf); }
inline void storeRate(u8* out, const State& s) { for (int j = 0; j < 8; j++) st32(out + 4 * j, s[j]); }

struct Aead {
    Set set; std::array<u32, 8> k{}; State s{}; int rl;
    Aead(Set set_, const u8 key[32], const u8 nonce[24], const Bytes& ad) : set(set_), rl(lightRounds(set_)) {
        for (int j = 0; j < 8; j++) k[j] = ld32(key + 4 * j);
        s[0] = IV0; s[1] = iv1(set);
        for (int j = 0; j < 8; j++) s[2 + j] = k[j];
        for (int j = 0; j < 6; j++) s[10 + j] = ld32(nonce + 4 * j);
        permute(s, 12);
        for (int j = 0; j < 8; j++) s[8 + j] ^= k[j];
        if (!ad.empty()) {
            size_t full = ad.size() / 32;
            for (size_t i = 0; i < full; i++) { xorRate(s, ad.data() + 32 * i); permute(s, rl); }
            xorRatePadded(s, ad.data() + 32 * full, ad.size() - 32 * full); permute(s, rl);
        }
        s[15] ^= 0x80000000u;
    }
    void finalize(u8 tag[32]) { for (int j = 0; j < 8; j++) s[8 + j] ^= k[j]; permute(s, 12); storeRate(tag, s); }
};

// Returns ciphertext || 32-byte tag.
inline Bytes encrypt(Set set, const u8 key[32], const u8 nonce[24], const Bytes& ad, const Bytes& m) {
    Aead a(set, key, nonce, ad);
    Bytes out(m.size() + 32);
    size_t full = m.size() / 32;
    for (size_t i = 0; i < full; i++) { xorRate(a.s, m.data() + 32 * i); storeRate(out.data() + 32 * i, a.s); permute(a.s, a.rl); }
    size_t rem = m.size() - 32 * full; u8 ks[32];
    xorRatePadded(a.s, m.data() + 32 * full, rem); storeRate(ks, a.s); std::memcpy(out.data() + 32 * full, ks, rem);
    a.finalize(out.data() + m.size());
    return out;
}
// Returns true and the plaintext, or false (empty plaintext) on authentication failure.
inline bool decrypt(Bytes& pt, Set set, const u8 key[32], const u8 nonce[24], const Bytes& ad, const Bytes& c) {
    if (c.size() < 32) return false;
    size_t blen = c.size() - 32; Aead a(set, key, nonce, ad);
    pt.assign(blen, 0);
    size_t full = blen / 32;
    for (size_t i = 0; i < full; i++) {
        for (int j = 0; j < 8; j++) { u32 cw = ld32(c.data() + 32 * i + 4 * j); st32(pt.data() + 32 * i + 4 * j, a.s[j] ^ cw); a.s[j] = cw; }
        permute(a.s, a.rl);
    }
    size_t rem = blen - 32 * full; u8 ks[32], last[32] = {0};
    storeRate(ks, a.s);
    for (size_t j = 0; j < rem; j++) last[j] = c[32 * full + j] ^ ks[j];
    xorRatePadded(a.s, last, rem);
    u8 exp[32]; a.finalize(exp);
    u8 d = 0; for (int j = 0; j < 32; j++) d |= exp[j] ^ c[blen + j];
    if (d) { pt.clear(); return false; }
    std::memcpy(pt.data() + 32 * full, last, rem);
    return true;
}

inline Bytes hash256(const Bytes& in) {
    State s{}; s[0] = IV0; s[1] = IV1_HASH;
    size_t full = in.size() / 32;
    for (size_t i = 0; i < full; i++) { xorRate(s, in.data() + 32 * i); permute(s, 12); }
    xorRatePadded(s, in.data() + 32 * full, in.size() - 32 * full); permute(s, 12);
    Bytes out(32); storeRate(out.data(), s); return out;
}

} // namespace fable

// ---------------- self-test ----------------
static std::string hex(const std::vector<uint8_t>& b) { static const char* h = "0123456789abcdef"; std::string s; for (auto x : b) { s += h[x >> 4]; s += h[x & 15]; } return s; }
static bool check(const char* name, const std::string& got, const std::string& exp) { bool ok = got == exp; std::printf("%-28s %s\n", name, ok ? "OK" : "FAIL"); return ok; }

int main() {
    using namespace fable;
    bool ok = true; u8 key[32], nonce[24];
    for (int i = 0; i < 32; i++) key[i] = u8(i); for (int i = 0; i < 24; i++) nonce[i] = u8(i);
    auto stateHex = [](const State& s) { Bytes b(64); for (int j = 0; j < 16; j++) st32(b.data() + 4 * j, s[j]); return hex(b); };
    State s{}; permute(s, 12);
    ok &= check("permute12_zero", stateHex(s), "987e1eab32cefb5c1476a1517c5d0c9f81d61cb4808b32b00db6745079ed44947ea9cb25720c64fe7bb9b86e3e1db2d345a9b4024a1f5849b1f77ecc6188a8fd");
    s = State{}; permute(s, 8);
    ok &= check("permute8_zero", stateHex(s), "13bf4c33b2ac964ca319d28c2e01c0732aaf9109228e083ec58861cabc663dd6a7bbce1ed69452d5975b4def6f81f40812bfceced5a62100a16f9ef2e066e302");
    Bytes m64(64); for (int i = 0; i < 64; i++) m64[i] = u8(i);
    Bytes hdr = {'h', 'e', 'a', 'd', 'e', 'r'};
    struct V { Set set; const char* name; Bytes ad; size_t mlen; const char* ct; } vs[] = {
        {Set::Fable, "fable/empty", {}, 0, "13233108192c9cd5274e9e830400ff2ac75147d59c6340000659b25887752cbb"},
        {Set::Fable, "fable/block", hdr, 32, "59358977baf9ca6b482719c0299011ab2dd25d2c03f933b17a3822ff0cfdd25448f4dfc93df45855b8f92ea1282cafaf5087a4077113e4b98949ddec135aaa37"},
        {Set::Fable, "fable/two_blocks", {}, 64, "cf86c83ad9cb6e9c81c97b6cfbbe993532718b96a49a95dbc19e3d8f68aa58381b12889a7d584bdeca7ee688c8c4f65def77ff1d86ef6efed67b89909ea972a5d7fa539b06346f3a96cdead2479a89468edf935c278085e44fe3557555938bdc"},
        {Set::FableF, "fable-f/empty", {}, 0, "1a053a4f55101f93539b2d67a051343194ccf0ac5d80a751c6ab1d5339bb1641"},
        {Set::FableF, "fable-f/block", hdr, 32, "9e43775b205f324f6fd91b0511fa4a401bf73905ea86c0066a2f94f49988c9263d6d58e99c0b8d8adf3dfb8df17ec96ef186b62d0118f8915c652a5b5a1ff768"},
        {Set::FableF, "fable-f/two_blocks", {}, 64, "323a0d285c881b5b74541171c37585e4b2e2f5b6c96de7cac16f09c913a539417a84e26b33299a848b701d1b852df32d2d5ff43202442fc5fdbf2350d149b8cdedd4ae05f26b61841783aed3d55d26b286bb5b25eb413c271547eaf293f448bd"},
    };
    for (auto& v : vs) {
        Bytes m(m64.begin(), m64.begin() + v.mlen);
        Bytes ct = encrypt(v.set, key, nonce, v.ad, m);
        ok &= check(v.name, hex(ct), v.ct);
        Bytes pt; bool rt = decrypt(pt, v.set, key, nonce, v.ad, ct) && pt == m;
        ct.back() ^= 1; bool tamper = !decrypt(pt, v.set, key, nonce, v.ad, ct);
        std::printf("%-28s %s\n", "  decrypt/tamper", rt && tamper ? "OK" : "FAIL"); ok &= rt && tamper;
    }
    ok &= check("hash256(abc)", hex(hash256({'a', 'b', 'c'})), "d0a959109d1b0729c6af6b74cc176c5cd1081cc262530530c80e3ad12566603d");
    ok &= check("hash256(empty)", hex(hash256({})), "22f0a458f9baa6ba8b5ebc2f4614f2643ede4628cba8dab7bd1bcaa5089c6607");
    std::printf("RESULT: %s\n", ok ? "ALL OK" : "FAILURES");
    return ok ? 0 : 1;
}
