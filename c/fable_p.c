/* Fable-P permutation, C reference (v0.1 spec §2). Research draft, NOT for production. */
#include "fable_p.h"

const uint32_t FABLE_RC[12] = {
    0xb17217f7u, 0x193ea7aau, 0x9c041f7eu, 0xf2272ae3u,
    0x65dc76efu, 0x90a08566u, 0xd54d783fu, 0xf1c6c0c0u,
    0x22afbfbau, 0x5e071979u, 0x6f19c912u, 0x9c651dc7u,
};

static inline uint32_t rotl32(uint32_t x, int n) {
    n &= 31;
    return n ? ((x << n) | (x >> (32 - n))) : x;
}

#define Q(a, b, c, d)                                   \
    do {                                                \
        a += b; d ^= a; d = rotl32(d, r0);              \
        c += d; b ^= c; b = rotl32(b, r1);              \
        a += b; d ^= a; d = rotl32(d, r2);              \
        c += d; b ^= c; b = rotl32(b, r3);              \
    } while (0)

static inline void fable_round(uint32_t s[16], uint32_t rc,
                               int r0, int r1, int r2, int r3) {
    uint32_t s0 = s[0], s1 = s[1], s2 = s[2], s3 = s[3];
    uint32_t s4 = s[4], s5 = s[5], s6 = s[6], s7 = s[7];
    uint32_t s8 = s[8], s9 = s[9], s10 = s[10], s11 = s[11];
    uint32_t s12 = s[12], s13 = s[13], s14 = s[14], s15 = s[15];

    s0 ^= rc;
    s5 ^= rotl32(rc, 16);

    /* column step */
    Q(s0, s4, s8, s12);  Q(s1, s5, s9, s13);
    Q(s2, s6, s10, s14); Q(s3, s7, s11, s15);
    /* diagonal step */
    Q(s0, s5, s10, s15); Q(s1, s6, s11, s12);
    Q(s2, s7, s8, s13);  Q(s3, s4, s9, s14);

    s[0] = s0; s[1] = s1; s[2] = s2; s[3] = s3;
    s[4] = s4; s[5] = s5; s[6] = s6; s[7] = s7;
    s[8] = s8; s[9] = s9; s[10] = s10; s[11] = s11;
    s[12] = s12; s[13] = s13; s[14] = s14; s[15] = s15;
}

void fable_permute_rot(uint32_t s[16], int rounds, int r0, int r1, int r2, int r3) {
    int start = FABLE_ROUNDS_HEAVY - rounds;
    for (int i = start; i < FABLE_ROUNDS_HEAVY; i++)
        fable_round(s, FABLE_RC[i], r0, r1, r2, r3);
}

void fable_permute_noconst(uint32_t s[16], int rounds, int r0, int r1, int r2, int r3) {
    for (int i = 0; i < rounds; i++)
        fable_round(s, 0u, r0, r1, r2, r3);
}

void fable_permute(uint32_t s[16], int rounds) {
    fable_permute_rot(s, rounds, FABLE_R0, FABLE_R1, FABLE_R2, FABLE_R3);
}
