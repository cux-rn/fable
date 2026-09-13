/* Fable-Stream, 8-way AVX2 (states resident in transposed layout), encrypt + decrypt, v0.3 sets. */
#include <string.h>
#include <immintrin.h>
#include "fable_stream_avx2.h"
#include "fable_p_avx2.h"

#define IV0_AEAD 0x4661626Cu
#define HDR 28

static inline uint32_t ld32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static inline void st32(uint8_t *p, uint32_t x) {
    p[0] = (uint8_t)x; p[1] = (uint8_t)(x >> 8); p[2] = (uint8_t)(x >> 16); p[3] = (uint8_t)(x >> 24);
}

/* 8x8 transpose of 32-bit elements (r[i] = row i -> r[j] = column j); an involution. */
static inline void transpose8x8(__m256i r[8]) {
    __m256i t[8], u[8];
    t[0] = _mm256_unpacklo_epi32(r[0], r[1]); t[1] = _mm256_unpackhi_epi32(r[0], r[1]);
    t[2] = _mm256_unpacklo_epi32(r[2], r[3]); t[3] = _mm256_unpackhi_epi32(r[2], r[3]);
    t[4] = _mm256_unpacklo_epi32(r[4], r[5]); t[5] = _mm256_unpackhi_epi32(r[4], r[5]);
    t[6] = _mm256_unpacklo_epi32(r[6], r[7]); t[7] = _mm256_unpackhi_epi32(r[6], r[7]);
    u[0] = _mm256_unpacklo_epi64(t[0], t[2]); u[1] = _mm256_unpackhi_epi64(t[0], t[2]);
    u[2] = _mm256_unpacklo_epi64(t[1], t[3]); u[3] = _mm256_unpackhi_epi64(t[1], t[3]);
    u[4] = _mm256_unpacklo_epi64(t[4], t[6]); u[5] = _mm256_unpackhi_epi64(t[4], t[6]);
    u[6] = _mm256_unpacklo_epi64(t[5], t[7]); u[7] = _mm256_unpackhi_epi64(t[5], t[7]);
    r[0] = _mm256_permute2x128_si256(u[0], u[4], 0x20); r[1] = _mm256_permute2x128_si256(u[1], u[5], 0x20);
    r[2] = _mm256_permute2x128_si256(u[2], u[6], 0x20); r[3] = _mm256_permute2x128_si256(u[3], u[7], 0x20);
    r[4] = _mm256_permute2x128_si256(u[0], u[4], 0x31); r[5] = _mm256_permute2x128_si256(u[1], u[5], 0x31);
    r[6] = _mm256_permute2x128_si256(u[2], u[6], 0x31); r[7] = _mm256_permute2x128_si256(u[3], u[7], 0x31);
}

static void make_header(uint8_t h[HDR], const uint8_t nf[19], uint32_t chunk) {
    memcpy(h, "FBLS", 4); h[4] = 1; st32(h + 5, chunk); memcpy(h + 9, nf, 19);
}
static void make_nonce(uint8_t n[24], const uint8_t nf[19], uint32_t ctr, int last) {
    memcpy(n, nf, 19); st32(n + 19, ctr); n[23] = last ? 1 : 0;
}

size_t fable_stream_output_size(size_t len, uint32_t chunk) {
    size_t n = len / chunk + 1;
    return HDR + len + 32 * n;
}

/* Init + AD for 8 lanes (chunks i0..i0+7, flag 0). */
static void init8(__m256i v[16], uint32_t k[8], int set, const uint8_t key[32], const uint8_t hdr[HDR],
                  const uint8_t nf[19], uint32_t i0) {
    int rl = fable_set_light_rounds(set);
    for (int j = 0; j < 8; j++) k[j] = ld32(key + 4 * j);
    v[0] = _mm256_set1_epi32((int)IV0_AEAD);
    v[1] = _mm256_set1_epi32((int)fable_set_iv1(set));
    for (int j = 0; j < 8; j++) v[2 + j] = _mm256_set1_epi32((int)k[j]);
    uint32_t nw[6][8];
    for (int l = 0; l < 8; l++) {
        uint8_t n[24]; make_nonce(n, nf, i0 + (uint32_t)l, 0);
        for (int j = 0; j < 6; j++) nw[j][l] = ld32(n + 4 * j);
    }
    for (int j = 0; j < 6; j++) v[10 + j] = _mm256_loadu_si256((const __m256i *)nw[j]);
    fable_permute_x8_t(v, FABLE_ROUNDS_HEAVY);
    for (int j = 0; j < 8; j++) v[8 + j] = _mm256_xor_si256(v[8 + j], _mm256_set1_epi32((int)k[j]));
    uint8_t blk[32] = {0}; memcpy(blk, hdr, HDR); blk[HDR] = 0x80;       /* AD = header, one block */
    for (int j = 0; j < 8; j++) v[j] = _mm256_xor_si256(v[j], _mm256_set1_epi32((int)ld32(blk + 4 * j)));
    fable_permute_x8_t(v, rl);
    v[15] = _mm256_xor_si256(v[15], _mm256_set1_epi32((int)0x80000000u));
}

/* Encrypt 8 full non-final chunks. in stride = chunk, out stride = chunk + 32. */
static void encrypt8(uint8_t *body, int set, const uint8_t key[32], const uint8_t hdr[HDR], const uint8_t nf[19],
                     const uint8_t *data, uint32_t chunk, uint32_t i0) {
    int rl = fable_set_light_rounds(set);
    uint32_t k[8]; __m256i v[16], r[8];
    init8(v, k, set, key, hdr, nf, i0);
    const uint8_t *in[8]; uint8_t *op[8];
    for (int l = 0; l < 8; l++) { in[l] = data + (size_t)(i0 + l) * chunk; op[l] = body + (size_t)(i0 + l) * ((size_t)chunk + 32); }
    uint32_t full = chunk / 32, rem = chunk % 32;
    for (uint32_t b = 0; b < full; b++) {
        for (int l = 0; l < 8; l++) r[l] = _mm256_loadu_si256((const __m256i *)(in[l] + (size_t)b * 32));
        transpose8x8(r);
        for (int w = 0; w < 8; w++) v[w] = _mm256_xor_si256(v[w], r[w]);
        for (int w = 0; w < 8; w++) r[w] = v[w];
        transpose8x8(r);
        for (int l = 0; l < 8; l++) _mm256_storeu_si256((__m256i *)(op[l] + (size_t)b * 32), r[l]);
        fable_permute_x8_t(v, rl);
    }
    uint8_t buf[8][32];
    for (int l = 0; l < 8; l++) {
        memset(buf[l], 0, 32); memcpy(buf[l], in[l] + (size_t)full * 32, rem); buf[l][rem] = 0x80;
        r[l] = _mm256_loadu_si256((const __m256i *)buf[l]);
    }
    transpose8x8(r);
    for (int w = 0; w < 8; w++) v[w] = _mm256_xor_si256(v[w], r[w]);
    if (rem) {
        for (int w = 0; w < 8; w++) r[w] = v[w];
        transpose8x8(r);
        for (int l = 0; l < 8; l++) { _mm256_storeu_si256((__m256i *)buf[l], r[l]); memcpy(op[l] + (size_t)full * 32, buf[l], rem); }
    }
    for (int j = 0; j < 8; j++) v[8 + j] = _mm256_xor_si256(v[8 + j], _mm256_set1_epi32((int)k[j]));
    fable_permute_x8_t(v, FABLE_ROUNDS_HEAVY);
    for (int w = 0; w < 8; w++) r[w] = v[w];
    transpose8x8(r);
    for (int l = 0; l < 8; l++) _mm256_storeu_si256((__m256i *)(op[l] + chunk), r[l]);
}

/* Decrypt 8 full non-final chunks. Returns 0 if all 8 tags verify, else nonzero. */
static int decrypt8(uint8_t *out, int set, const uint8_t key[32], const uint8_t hdr[HDR], const uint8_t nf[19],
                    const uint8_t *body, uint32_t chunk, uint32_t i0) {
    int rl = fable_set_light_rounds(set);
    uint32_t k[8]; __m256i v[16], r[8];
    init8(v, k, set, key, hdr, nf, i0);
    const uint8_t *in[8]; uint8_t *op[8];
    for (int l = 0; l < 8; l++) { in[l] = body + (size_t)(i0 + l) * ((size_t)chunk + 32); op[l] = out + (size_t)(i0 + l) * chunk; }
    uint32_t full = chunk / 32, rem = chunk % 32;
    for (uint32_t b = 0; b < full; b++) {
        for (int l = 0; l < 8; l++) r[l] = _mm256_loadu_si256((const __m256i *)(in[l] + (size_t)b * 32));
        transpose8x8(r);                                   /* r[w] = ciphertext word w */
        __m256i p[8];
        for (int w = 0; w < 8; w++) { p[w] = _mm256_xor_si256(v[w], r[w]); v[w] = r[w]; }
        transpose8x8(p);
        for (int l = 0; l < 8; l++) _mm256_storeu_si256((__m256i *)(op[l] + (size_t)b * 32), p[l]);
        fable_permute_x8_t(v, rl);
    }
    /* partial last block: p = ks ^ c (rem bytes), then rate ^= pad(p) */
    uint8_t buf[8][32];
    for (int w = 0; w < 8; w++) r[w] = v[w];
    transpose8x8(r);
    for (int l = 0; l < 8; l++) {
        uint8_t ks[32]; _mm256_storeu_si256((__m256i *)ks, r[l]);
        memset(buf[l], 0, 32);
        for (uint32_t j = 0; j < rem; j++) buf[l][j] = in[l][(size_t)full * 32 + j] ^ ks[j];
        memcpy(op[l] + (size_t)full * 32, buf[l], rem);
        buf[l][rem] = 0x80;
        r[l] = _mm256_loadu_si256((const __m256i *)buf[l]);
    }
    transpose8x8(r);
    for (int w = 0; w < 8; w++) v[w] = _mm256_xor_si256(v[w], r[w]);
    for (int j = 0; j < 8; j++) v[8 + j] = _mm256_xor_si256(v[8 + j], _mm256_set1_epi32((int)k[j]));
    fable_permute_x8_t(v, FABLE_ROUNDS_HEAVY);
    for (int w = 0; w < 8; w++) r[w] = v[w];
    transpose8x8(r);
    uint8_t bad = 0;
    for (int l = 0; l < 8; l++) {
        uint8_t tag[32]; _mm256_storeu_si256((__m256i *)tag, r[l]);
        for (int j = 0; j < 32; j++) bad |= tag[j] ^ in[l][chunk + j];
    }
    return bad;
}

static size_t stream_encrypt(uint8_t *out, int set, const uint8_t key[32], const uint8_t nf[19],
                             const uint8_t *data, size_t len, uint32_t chunk, int use_x8) {
    uint8_t hdr[HDR]; make_header(hdr, nf, chunk);
    memcpy(out, hdr, HDR);
    size_t n = len / chunk + 1;
    uint8_t *body = out + HDR;
    size_t i = 0;
    if (use_x8) while (i + 8 <= n - 1) { encrypt8(body, set, key, hdr, nf, data, chunk, (uint32_t)i); i += 8; }
    for (; i < n; i++) {
        int last = (i == n - 1);
        size_t mlen = last ? len - i * (size_t)chunk : chunk;
        uint8_t nonce[24]; make_nonce(nonce, nf, (uint32_t)i, last);
        fable_aead_encrypt_set(body + i * ((size_t)chunk + 32), set, key, nonce, hdr, HDR, data + i * (size_t)chunk, mlen);
    }
    return HDR + len + 32 * n;
}

static long long stream_decrypt(uint8_t *out, int set, const uint8_t key[32], const uint8_t *blob, size_t bloblen, int use_x8) {
    if (bloblen < HDR || memcmp(blob, "FBLS", 4) != 0 || blob[4] != 1) return -1;
    uint32_t chunk = ld32(blob + 5);
    if (chunk == 0) return -1;
    const uint8_t *nf = blob + 9, *hdr = blob, *body = blob + HDR;
    size_t bodylen = bloblen - HDR, step = (size_t)chunk + 32;
    size_t nfull = bodylen / step, rem = bodylen % step;
    if (rem < 32) return -1;                       /* missing final chunk (rem == 0) or truncated */
    size_t mlast = rem - 32, plen = nfull * (size_t)chunk + mlast;
    int bad = 0;
    size_t i = 0;
    if (use_x8) while (i + 8 <= nfull) { bad |= decrypt8(out, set, key, hdr, nf, body, chunk, (uint32_t)i); i += 8; }
    for (; i < nfull; i++) {
        uint8_t nonce[24]; make_nonce(nonce, nf, (uint32_t)i, 0);
        bad |= fable_aead_decrypt_set(out + i * (size_t)chunk, set, key, nonce, hdr, HDR, body + i * step, step) != 0;
    }
    {
        uint8_t nonce[24]; make_nonce(nonce, nf, (uint32_t)nfull, 1);
        bad |= fable_aead_decrypt_set(out + nfull * (size_t)chunk, set, key, nonce, hdr, HDR, body + nfull * step, rem) != 0;
    }
    if (bad) { memset(out, 0, plen); return -1; }
    return (long long)plen;
}

size_t fable_stream_encrypt_x8_set(uint8_t *out, int set, const uint8_t key[32], const uint8_t nf[19],
                                   const uint8_t *data, size_t len, uint32_t chunk) {
    return stream_encrypt(out, set, key, nf, data, len, chunk, 1);
}
size_t fable_stream_encrypt_scalar_set(uint8_t *out, int set, const uint8_t key[32], const uint8_t nf[19],
                                       const uint8_t *data, size_t len, uint32_t chunk) {
    return stream_encrypt(out, set, key, nf, data, len, chunk, 0);
}
long long fable_stream_decrypt_x8_set(uint8_t *out, int set, const uint8_t key[32], const uint8_t *blob, size_t bloblen) {
    return stream_decrypt(out, set, key, blob, bloblen, 1);
}
long long fable_stream_decrypt_scalar_set(uint8_t *out, int set, const uint8_t key[32], const uint8_t *blob, size_t bloblen) {
    return stream_decrypt(out, set, key, blob, bloblen, 0);
}
size_t fable_stream_encrypt_x8(uint8_t *out, const uint8_t key[32], const uint8_t nf[19],
                               const uint8_t *data, size_t len, uint32_t chunk) {
    return stream_encrypt(out, FABLE_SET_DEFAULT, key, nf, data, len, chunk, 1);
}
size_t fable_stream_encrypt_scalar(uint8_t *out, const uint8_t key[32], const uint8_t nf[19],
                                   const uint8_t *data, size_t len, uint32_t chunk) {
    return stream_encrypt(out, FABLE_SET_DEFAULT, key, nf, data, len, chunk, 0);
}
