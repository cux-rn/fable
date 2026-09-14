/* Fable v0.5 — single-file C example: Fable-P, Fable-AEAD (both parameter sets), Fable-Hash-256.
 * Research draft, NOT for production. Self-test against test_vectors_v0.3.json values.
 * Build: clang -O2 -std=c11 fable_example.c -o fable_example && ./fable_example
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static const uint32_t RC[12] = {
    0xb17217f7u, 0x193ea7aau, 0x9c041f7eu, 0xf2272ae3u, 0x65dc76efu, 0x90a08566u,
    0xd54d783fu, 0xf1c6c0c0u, 0x22afbfbau, 0x5e071979u, 0x6f19c912u, 0x9c651dc7u};
#define IV0 0x4661626Cu
#define IV1_FABLE 0x012020C8u   /* P_12 / P_8 (default set) */
#define IV1_FABLE_F 0x012020C6u /* P_12 / P_6 (Fable-f) */
#define IV1_HASH 0x01202000u

enum { FABLE = 0, FABLE_F = 1 };
static int light_rounds(int set) { return set == FABLE_F ? 6 : 8; }
static uint32_t iv1(int set) { return set == FABLE_F ? IV1_FABLE_F : IV1_FABLE; }

static inline uint32_t rotl(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }
#define Q(a, b, c, d) do { \
    a += b; d ^= a; d = rotl(d, 16); c += d; b ^= c; b = rotl(b, 12); \
    a += b; d ^= a; d = rotl(d, 8);  c += d; b ^= c; b = rotl(b, 7); } while (0)

/* Fable-P: `rounds` rounds using the LAST `rounds` constants (P_8 -> RC[4..11], P_6 -> RC[6..11]). */
void fable_permute(uint32_t s[16], int rounds) {
    for (int i = 12 - rounds; i < 12; i++) {
        s[0] ^= RC[i]; s[5] ^= rotl(RC[i], 16);
        Q(s[0], s[4], s[8], s[12]);  Q(s[1], s[5], s[9], s[13]);
        Q(s[2], s[6], s[10], s[14]); Q(s[3], s[7], s[11], s[15]);
        Q(s[0], s[5], s[10], s[15]); Q(s[1], s[6], s[11], s[12]);
        Q(s[2], s[7], s[8], s[13]);  Q(s[3], s[4], s[9], s[14]);
    }
}

static uint32_t ld32(const uint8_t *p) { return p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24; }
static void st32(uint8_t *p, uint32_t x) { p[0] = x; p[1] = x >> 8; p[2] = x >> 16; p[3] = x >> 24; }
static void xor_rate(uint32_t s[16], const uint8_t *blk) { for (int j = 0; j < 8; j++) s[j] ^= ld32(blk + 4 * j); }
static void xor_rate_padded(uint32_t s[16], const uint8_t *blk, size_t len) {   /* len < 32, 10* padding */
    uint8_t buf[32] = {0}; memcpy(buf, blk, len); buf[len] = 0x80; xor_rate(s, buf);
}
static void store_rate(uint8_t *out, const uint32_t s[16]) { for (int j = 0; j < 8; j++) st32(out + 4 * j, s[j]); }

static void aead_init(uint32_t s[16], uint32_t k[8], int set, const uint8_t key[32], const uint8_t nonce[24]) {
    for (int j = 0; j < 8; j++) k[j] = ld32(key + 4 * j);
    s[0] = IV0; s[1] = iv1(set);
    for (int j = 0; j < 8; j++) s[2 + j] = k[j];
    for (int j = 0; j < 6; j++) s[10 + j] = ld32(nonce + 4 * j);
    fable_permute(s, 12);
    for (int j = 0; j < 8; j++) s[8 + j] ^= k[j];
}
static void absorb_ad(uint32_t s[16], int rl, const uint8_t *ad, size_t adlen) {
    if (adlen) {
        size_t full = adlen / 32;
        for (size_t i = 0; i < full; i++) { xor_rate(s, ad + 32 * i); fable_permute(s, rl); }
        xor_rate_padded(s, ad + 32 * full, adlen - 32 * full); fable_permute(s, rl);
    }
    s[15] ^= 0x80000000u;
}
static void finalize(uint8_t tag[32], uint32_t s[16], const uint32_t k[8]) {
    for (int j = 0; j < 8; j++) s[8 + j] ^= k[j];
    fable_permute(s, 12);
    store_rate(tag, s);
}

/* out: mlen + 32 bytes (ciphertext || tag). */
void fable_aead_encrypt(uint8_t *out, int set, const uint8_t key[32], const uint8_t nonce[24],
                        const uint8_t *ad, size_t adlen, const uint8_t *m, size_t mlen) {
    uint32_t s[16], k[8]; int rl = light_rounds(set);
    aead_init(s, k, set, key, nonce); absorb_ad(s, rl, ad, adlen);
    size_t full = mlen / 32, pos = 0;
    for (size_t i = 0; i < full; i++) { xor_rate(s, m + 32 * i); store_rate(out + pos, s); pos += 32; fable_permute(s, rl); }
    size_t rem = mlen - 32 * full; uint8_t ks[32];
    xor_rate_padded(s, m + 32 * full, rem); store_rate(ks, s); memcpy(out + pos, ks, rem); pos += rem;
    finalize(out + pos, s, k);
}
/* Returns 0 and writes clen-32 plaintext bytes, or -1 (out zeroed) on authentication failure. */
int fable_aead_decrypt(uint8_t *out, int set, const uint8_t key[32], const uint8_t nonce[24],
                       const uint8_t *ad, size_t adlen, const uint8_t *c, size_t clen) {
    if (clen < 32) return -1;
    size_t blen = clen - 32; uint32_t s[16], k[8]; int rl = light_rounds(set);
    aead_init(s, k, set, key, nonce); absorb_ad(s, rl, ad, adlen);
    size_t full = blen / 32;
    for (size_t i = 0; i < full; i++) {
        for (int j = 0; j < 8; j++) { uint32_t cw = ld32(c + 32 * i + 4 * j); st32(out + 32 * i + 4 * j, s[j] ^ cw); s[j] = cw; }
        fable_permute(s, rl);
    }
    size_t rem = blen - 32 * full; uint8_t ks[32], lastp[32];
    store_rate(ks, s);
    for (size_t j = 0; j < rem; j++) lastp[j] = c[32 * full + j] ^ ks[j];
    xor_rate_padded(s, lastp, rem);
    uint8_t exp[32]; finalize(exp, s, k);
    uint8_t d = 0; for (int j = 0; j < 32; j++) d |= exp[j] ^ c[blen + j];   /* constant time */
    if (d) { memset(out, 0, blen); return -1; }
    memcpy(out + 32 * full, lastp, rem);
    return 0;
}

void fable_hash256(uint8_t out[32], const uint8_t *in, size_t inlen) {
    uint32_t s[16] = {0}; s[0] = IV0; s[1] = IV1_HASH;
    size_t full = inlen / 32;
    for (size_t i = 0; i < full; i++) { xor_rate(s, in + 32 * i); fable_permute(s, 12); }
    xor_rate_padded(s, in + 32 * full, inlen - 32 * full); fable_permute(s, 12);
    store_rate(out, s);
}

/* ---------------- self-test ---------------- */
static int unhex(uint8_t *out, const char *hex) { size_t n = strlen(hex) / 2; for (size_t i = 0; i < n; i++) sscanf(hex + 2 * i, "%2hhx", &out[i]); return (int)n; }
static int check(const char *name, const uint8_t *got, const char *exp_hex) {
    uint8_t exp[256]; int n = unhex(exp, exp_hex); int ok = memcmp(got, exp, n) == 0;
    printf("%-28s %s\n", name, ok ? "OK" : "FAIL"); return ok;
}
int main(void) {
    int ok = 1; uint8_t key[32], nonce[24], buf[128], pt[128], hb[32];
    for (int i = 0; i < 32; i++) key[i] = i; for (int i = 0; i < 24; i++) nonce[i] = i;
    uint32_t s[16] = {0}; fable_permute(s, 12); store_rate(buf, s); for (int j = 8; j < 16; j++) st32(buf + 4 * j, s[j]);
    ok &= check("permute12_zero", buf, "987e1eab32cefb5c1476a1517c5d0c9f81d61cb4808b32b00db6745079ed44947ea9cb25720c64fe7bb9b86e3e1db2d345a9b4024a1f5849b1f77ecc6188a8fd");
    memset(s, 0, sizeof s); fable_permute(s, 8); for (int j = 0; j < 16; j++) st32(buf + 4 * j, s[j]);
    ok &= check("permute8_zero", buf, "13bf4c33b2ac964ca319d28c2e01c0732aaf9109228e083ec58861cabc663dd6a7bbce1ed69452d5975b4def6f81f40812bfceced5a62100a16f9ef2e066e302");
    uint8_t m64[64]; for (int i = 0; i < 64; i++) m64[i] = i;
    struct { int set; const char *name; const uint8_t *ad; size_t adlen; size_t mlen; const char *ct; } v[] = {
        {FABLE, "fable/empty", (const uint8_t *)"", 0, 0, "13233108192c9cd5274e9e830400ff2ac75147d59c6340000659b25887752cbb"},
        {FABLE, "fable/block", (const uint8_t *)"header", 6, 32, "59358977baf9ca6b482719c0299011ab2dd25d2c03f933b17a3822ff0cfdd25448f4dfc93df45855b8f92ea1282cafaf5087a4077113e4b98949ddec135aaa37"},
        {FABLE, "fable/two_blocks", (const uint8_t *)"", 0, 64, "cf86c83ad9cb6e9c81c97b6cfbbe993532718b96a49a95dbc19e3d8f68aa58381b12889a7d584bdeca7ee688c8c4f65def77ff1d86ef6efed67b89909ea972a5d7fa539b06346f3a96cdead2479a89468edf935c278085e44fe3557555938bdc"},
        {FABLE_F, "fable-f/empty", (const uint8_t *)"", 0, 0, "1a053a4f55101f93539b2d67a051343194ccf0ac5d80a751c6ab1d5339bb1641"},
        {FABLE_F, "fable-f/block", (const uint8_t *)"header", 6, 32, "9e43775b205f324f6fd91b0511fa4a401bf73905ea86c0066a2f94f49988c9263d6d58e99c0b8d8adf3dfb8df17ec96ef186b62d0118f8915c652a5b5a1ff768"},
        {FABLE_F, "fable-f/two_blocks", (const uint8_t *)"", 0, 64, "323a0d285c881b5b74541171c37585e4b2e2f5b6c96de7cac16f09c913a539417a84e26b33299a848b701d1b852df32d2d5ff43202442fc5fdbf2350d149b8cdedd4ae05f26b61841783aed3d55d26b286bb5b25eb413c271547eaf293f448bd"},
    };
    for (size_t i = 0; i < sizeof v / sizeof v[0]; i++) {
        fable_aead_encrypt(buf, v[i].set, key, nonce, v[i].ad, v[i].adlen, m64, v[i].mlen);
        ok &= check(v[i].name, buf, v[i].ct);
        int r = fable_aead_decrypt(pt, v[i].set, key, nonce, v[i].ad, v[i].adlen, buf, v[i].mlen + 32);
        int rt = r == 0 && memcmp(pt, m64, v[i].mlen) == 0;
        buf[v[i].mlen + 31] ^= 1;
        int tamper = fable_aead_decrypt(pt, v[i].set, key, nonce, v[i].ad, v[i].adlen, buf, v[i].mlen + 32) == -1;
        printf("%-28s %s\n", "  decrypt/tamper", rt && tamper ? "OK" : "FAIL"); ok &= rt && tamper;
    }
    fable_hash256(hb, (const uint8_t *)"abc", 3);
    ok &= check("hash256(abc)", hb, "d0a959109d1b0729c6af6b74cc176c5cd1081cc262530530c80e3ad12566603d");
    fable_hash256(hb, (const uint8_t *)"", 0);
    ok &= check("hash256(empty)", hb, "22f0a458f9baa6ba8b5ebc2f4614f2643ede4628cba8dab7bd1bcaa5089c6607");
    printf("RESULT: %s\n", ok ? "ALL OK" : "FAILURES");
    return ok ? 0 : 1;
}
