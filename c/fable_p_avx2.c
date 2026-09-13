/* Fable-P, AVX2 8-way: 16 __m256i registers hold 8 independent states (lane = state).
 * Rotations by 16 and 8 use byte shuffles (vpshufb), 12 and 7 use shift+or.
 * Same semantics as fable_permute(): round i uses RC[12 - rounds + i]. */
#include <immintrin.h>
#include <string.h>
#include "fable_p.h"
#include "fable_p_avx2.h"

#define ROT16(x) _mm256_shuffle_epi8((x), _mm256_set_epi8( \
    13, 12, 15, 14, 9, 8, 11, 10, 5, 4, 7, 6, 1, 0, 3, 2,      \
    13, 12, 15, 14, 9, 8, 11, 10, 5, 4, 7, 6, 1, 0, 3, 2))
#define ROT8(x) _mm256_shuffle_epi8((x), _mm256_set_epi8( \
    14, 13, 12, 15, 10, 9, 8, 11, 6, 5, 4, 7, 2, 1, 0, 3,      \
    14, 13, 12, 15, 10, 9, 8, 11, 6, 5, 4, 7, 2, 1, 0, 3))
#define ROTN(x, n) _mm256_or_si256(_mm256_slli_epi32((x), (n)), _mm256_srli_epi32((x), 32 - (n)))

#define QV(a, b, c, d)                                                        \
    do {                                                                      \
        a = _mm256_add_epi32(a, b); d = _mm256_xor_si256(d, a); d = ROT16(d); \
        c = _mm256_add_epi32(c, d); b = _mm256_xor_si256(b, c); b = ROTN(b, 12); \
        a = _mm256_add_epi32(a, b); d = _mm256_xor_si256(d, a); d = ROT8(d);  \
        c = _mm256_add_epi32(c, d); b = _mm256_xor_si256(b, c); b = ROTN(b, 7); \
    } while (0)

void fable_permute_x8_t(__m256i v[16], int rounds) {
    __m256i v0 = v[0], v1 = v[1], v2 = v[2], v3 = v[3], v4 = v[4], v5 = v[5], v6 = v[6], v7 = v[7];
    __m256i v8 = v[8], v9 = v[9], v10 = v[10], v11 = v[11], v12 = v[12], v13 = v[13], v14 = v[14], v15 = v[15];
    int start = FABLE_ROUNDS_HEAVY - rounds;
    for (int i = start; i < FABLE_ROUNDS_HEAVY; i++) {
        uint32_t rc = FABLE_RC[i];
        v0 = _mm256_xor_si256(v0, _mm256_set1_epi32((int)rc));
        v5 = _mm256_xor_si256(v5, _mm256_set1_epi32((int)((rc << 16) | (rc >> 16))));
        QV(v0, v4, v8, v12);  QV(v1, v5, v9, v13);
        QV(v2, v6, v10, v14); QV(v3, v7, v11, v15);
        QV(v0, v5, v10, v15); QV(v1, v6, v11, v12);
        QV(v2, v7, v8, v13);  QV(v3, v4, v9, v14);
    }
    v[0] = v0; v[1] = v1; v[2] = v2; v[3] = v3; v[4] = v4; v[5] = v5; v[6] = v6; v[7] = v7;
    v[8] = v8; v[9] = v9; v[10] = v10; v[11] = v11; v[12] = v12; v[13] = v13; v[14] = v14; v[15] = v15;
}

void fable_permute_x8(uint32_t st[8][16], int rounds) {
    __m256i v[16];
    /* transpose in: v[w] = (st[0][w], st[1][w], ..., st[7][w]) */
    for (int w = 0; w < 16; w++)
        v[w] = _mm256_set_epi32((int)st[7][w], (int)st[6][w], (int)st[5][w], (int)st[4][w],
                                (int)st[3][w], (int)st[2][w], (int)st[1][w], (int)st[0][w]);
    fable_permute_x8_t(v, rounds);
    for (int w = 0; w < 16; w++) {
        uint32_t tmp[8];
        _mm256_storeu_si256((__m256i *)tmp, v[w]);
        for (int l = 0; l < 8; l++) st[l][w] = tmp[l];
    }
}
