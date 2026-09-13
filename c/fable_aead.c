/* Fable-AEAD / Fable-XOF, C port of fable.py (v0.3). Research draft, NOT for production. */
#include <string.h>
#include "fable_aead.h"

#define IV0_AEAD 0x4661626Cu
#define IV1_HASH 0x01202000u
#define RATE_BYTES 32

int fable_set_light_rounds(int set) { return set == FABLE_SET_F ? 6 : 8; }
uint32_t fable_set_iv1(int set) { return set == FABLE_SET_F ? 0x012020C6u : 0x012020C8u; }

static uint32_t ld32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static void st32(uint8_t *p, uint32_t x) {
    p[0] = (uint8_t)x; p[1] = (uint8_t)(x >> 8); p[2] = (uint8_t)(x >> 16); p[3] = (uint8_t)(x >> 24);
}

/* XOR `len` (<32) bytes into the rate, then 10* padding byte, matching fable._pad. */
static void xor_rate_padded(uint32_t s[16], const uint8_t *blk, size_t len) {
    uint8_t buf[RATE_BYTES] = {0};
    memcpy(buf, blk, len);
    buf[len] = 0x80;
    for (int j = 0; j < 8; j++) s[j] ^= ld32(buf + 4 * j);
}
static void xor_rate(uint32_t s[16], const uint8_t *blk) {
    for (int j = 0; j < 8; j++) s[j] ^= ld32(blk + 4 * j);
}
static void store_rate(uint8_t *out, const uint32_t s[16]) {
    for (int j = 0; j < 8; j++) st32(out + 4 * j, s[j]);
}

static void aead_init(uint32_t s[16], uint32_t k[8], int set, const uint8_t key[32], const uint8_t nonce[24]) {
    for (int j = 0; j < 8; j++) k[j] = ld32(key + 4 * j);
    s[0] = IV0_AEAD; s[1] = fable_set_iv1(set);
    for (int j = 0; j < 8; j++) s[2 + j] = k[j];
    for (int j = 0; j < 6; j++) s[10 + j] = ld32(nonce + 4 * j);
    fable_permute(s, FABLE_ROUNDS_HEAVY);
    for (int j = 0; j < 8; j++) s[8 + j] ^= k[j];
}

static void absorb_ad(uint32_t s[16], int rl, const uint8_t *ad, size_t adlen) {
    if (adlen) {
        size_t full = adlen / RATE_BYTES;
        for (size_t i = 0; i < full; i++) {
            xor_rate(s, ad + i * RATE_BYTES);
            fable_permute(s, rl);
        }
        xor_rate_padded(s, ad + full * RATE_BYTES, adlen - full * RATE_BYTES);
        fable_permute(s, rl);
    }
    s[15] ^= 0x80000000u;
}

static void finalize(uint8_t tag[32], uint32_t s[16], const uint32_t k[8]) {
    for (int j = 0; j < 8; j++) s[8 + j] ^= k[j];
    fable_permute(s, FABLE_ROUNDS_HEAVY);
    store_rate(tag, s);
}

size_t fable_aead_encrypt_set(uint8_t *out, int set, const uint8_t key[32], const uint8_t nonce[24],
                              const uint8_t *ad, size_t adlen, const uint8_t *m, size_t mlen) {
    uint32_t s[16], k[8];
    int rl = fable_set_light_rounds(set);
    aead_init(s, k, set, key, nonce);
    absorb_ad(s, rl, ad, adlen);
    size_t full = mlen / RATE_BYTES, pos = 0;
    for (size_t i = 0; i < full; i++) {
        xor_rate(s, m + i * RATE_BYTES);
        store_rate(out + pos, s);
        pos += RATE_BYTES;
        fable_permute(s, rl);
    }
    size_t rem = mlen - full * RATE_BYTES;
    xor_rate_padded(s, m + full * RATE_BYTES, rem);
    {
        uint8_t ks[RATE_BYTES];
        store_rate(ks, s);
        memcpy(out + pos, ks, rem);
        pos += rem;
    }
    finalize(out + pos, s, k);
    return pos + FABLE_TAG_BYTES;
}

int fable_aead_decrypt_set(uint8_t *out, int set, const uint8_t key[32], const uint8_t nonce[24],
                           const uint8_t *ad, size_t adlen, const uint8_t *c, size_t clen) {
    if (clen < FABLE_TAG_BYTES) return -1;
    size_t blen = clen - FABLE_TAG_BYTES;
    const uint8_t *tag = c + blen;
    uint32_t s[16], k[8];
    int rl = fable_set_light_rounds(set);
    aead_init(s, k, set, key, nonce);
    absorb_ad(s, rl, ad, adlen);
    size_t full = blen / RATE_BYTES;
    for (size_t i = 0; i < full; i++) {
        for (int j = 0; j < 8; j++) {
            uint32_t cw = ld32(c + i * RATE_BYTES + 4 * j);
            st32(out + i * RATE_BYTES + 4 * j, s[j] ^ cw);
            s[j] = cw;
        }
        fable_permute(s, rl);
    }
    size_t rem = blen - full * RATE_BYTES;
    uint8_t ks[RATE_BYTES], lastp[RATE_BYTES];
    store_rate(ks, s);
    for (size_t j = 0; j < rem; j++) lastp[j] = c[full * RATE_BYTES + j] ^ ks[j];
    xor_rate_padded(s, lastp, rem);
    uint8_t exp[FABLE_TAG_BYTES];
    finalize(exp, s, k);
    uint8_t diff = 0;
    for (int j = 0; j < FABLE_TAG_BYTES; j++) diff |= exp[j] ^ tag[j];
    if (diff) {
        memset(out, 0, blen);
        return -1;
    }
    memcpy(out + full * RATE_BYTES, lastp, rem);
    return 0;
}

size_t fable_aead_encrypt(uint8_t *out, const uint8_t key[32], const uint8_t nonce[24],
                          const uint8_t *ad, size_t adlen, const uint8_t *m, size_t mlen) {
    return fable_aead_encrypt_set(out, FABLE_SET_DEFAULT, key, nonce, ad, adlen, m, mlen);
}
int fable_aead_decrypt(uint8_t *out, const uint8_t key[32], const uint8_t nonce[24],
                       const uint8_t *ad, size_t adlen, const uint8_t *c, size_t clen) {
    return fable_aead_decrypt_set(out, FABLE_SET_DEFAULT, key, nonce, ad, adlen, c, clen);
}

void fable_xof(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen) {
    uint32_t s[16] = {0};
    s[0] = IV0_AEAD; s[1] = IV1_HASH;
    size_t full = inlen / RATE_BYTES;
    for (size_t i = 0; i < full; i++) {
        xor_rate(s, in + i * RATE_BYTES);
        fable_permute(s, FABLE_ROUNDS_HEAVY);
    }
    xor_rate_padded(s, in + full * RATE_BYTES, inlen - full * RATE_BYTES);
    fable_permute(s, FABLE_ROUNDS_HEAVY);
    size_t pos = 0;
    while (pos < outlen) {
        uint8_t blk[RATE_BYTES];
        store_rate(blk, s);
        size_t n = outlen - pos < RATE_BYTES ? outlen - pos : RATE_BYTES;
        memcpy(out + pos, blk, n);
        pos += n;
        if (pos < outlen) fable_permute(s, FABLE_ROUNDS_HEAVY);
    }
}
