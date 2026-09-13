/* Fable-P, AVX2 8-state parallel version (each __m256i lane = one state's word). */
#ifndef FABLE_P_AVX2_H
#define FABLE_P_AVX2_H
#include <stdint.h>
#include <immintrin.h>
#ifdef __cplusplus
extern "C" {
#endif
/* Core: v[w] holds word w of 8 states (lane l = state l). Rounds as fable_permute(). */
void fable_permute_x8_t(__m256i v[16], int rounds);
/* Convenience: st[l][w] = word w of state l; transposes in and out around the core. */
void fable_permute_x8(uint32_t st[8][16], int rounds);
#ifdef __cplusplus
}
#endif
#endif
