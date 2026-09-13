/* Single-bit differential-linear bias of Fable-P over 1..4 "single rounds"
 * (single round = column step or diagonal step, as in ChaCha counting).
 *   eps(i,j) = Pr[ out_j(P(x)) ^ out_j(P(x ^ e_i)) = 0 ] - 1/2
 * for every input bit i (0..511) and output bit j (0..511), N samples per input bit.
 * Usage: dl_bias <single_rounds> <samples> <seed> <out_counts.u32> [noconst] [ib_lo ib_hi]
 *   single_rounds: 1 = column step (with constant injection), 2 = one full Fable round,
 *                  3 = round + column step, 4 = two full rounds.
 *   noconst: use zero round constants (ChaCha-like structure) for comparison.
 *   ib_lo/ib_hi: restrict input bits to [lo,hi) (for multi-process runs).
 * Output file: 512*512 uint32 counts of "output bit unchanged" (row = input bit).
 * Round constants used: the first `ceil(single_rounds/2)` of the P_12 suffix, i.e. the same
 * RC indices fable_permute(s, rounds) uses for `rounds` = ceil(single_rounds/2).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <math.h>
#include "fable_p.h"

static uint64_t rs[4];
static inline uint64_t rotl64(uint64_t x, int k) { return (x << k) | (x >> (64 - k)); }
static uint64_t next64(void) {
    uint64_t r = rotl64(rs[1] * 5, 7) * 9, t = rs[1] << 17;
    rs[2] ^= rs[0]; rs[3] ^= rs[1]; rs[1] ^= rs[2]; rs[0] ^= rs[3]; rs[2] ^= t; rs[3] = rotl64(rs[3], 45);
    return r;
}
static void seed(uint64_t s) {
    for (int i = 0; i < 4; i++) { s += 0x9E3779B97F4A7C15ull; uint64_t z = s;
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull; z = (z ^ (z >> 27)) * 0x94D049BB133111EBull; rs[i] = z ^ (z >> 31); }
}
static inline uint32_t rotl32(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }
#define Q(a, b, c, d) do { \
    a += b; d ^= a; d = rotl32(d, 16); c += d; b ^= c; b = rotl32(b, 12); \
    a += b; d ^= a; d = rotl32(d, 8);  c += d; b ^= c; b = rotl32(b, 7); } while (0)

/* single_rounds half-steps starting at RC index `rc0`; constants injected before each column step */
static void perm_half(uint32_t s[16], int single_rounds, int rc0, int noconst) {
    int rc = rc0;
    for (int h = 0; h < single_rounds; h++) {
        if ((h & 1) == 0) {
            if (!noconst) { s[0] ^= FABLE_RC[rc]; s[5] ^= rotl32(FABLE_RC[rc], 16); }
            rc++;
            Q(s[0], s[4], s[8], s[12]);  Q(s[1], s[5], s[9], s[13]);
            Q(s[2], s[6], s[10], s[14]); Q(s[3], s[7], s[11], s[15]);
        } else {
            Q(s[0], s[5], s[10], s[15]); Q(s[1], s[6], s[11], s[12]);
            Q(s[2], s[7], s[8], s[13]);  Q(s[3], s[4], s[9], s[14]);
        }
    }
}

int main(int argc, char **argv) {
    if (argc < 5) { fprintf(stderr, "usage: %s single_rounds samples seed out.u32 [noconst] [ib_lo ib_hi]\n", argv[0]); return 2; }
    int sr = atoi(argv[1]); long N = atol(argv[2]); uint64_t sd = strtoull(argv[3], 0, 10);
    int noconst = argc > 5 && (strcmp(argv[5], "noconst") == 0 || strcmp(argv[5], "chacha") == 0);
    /* chacha mode: genuine ChaCha state layout -- words 0..3 fixed to sigma constants
     * "expand 32-byte k", words 4..15 (key, counter, nonce) random, no round constants. */
    int chacha = argc > 5 && strcmp(argv[5], "chacha") == 0;
    static const uint32_t SIGMA[4] = {0x61707865u, 0x3320646eu, 0x79622d32u, 0x6b206574u};
    int lo = 0, hi = 512;
    if (argc > 7) { lo = atoi(argv[6]); hi = atoi(argv[7]); }
    int rounds = (sr + 1) / 2, rc0 = FABLE_ROUNDS_HEAVY - rounds;
    seed(sd);
    static uint32_t cnt[512][512];
    memset(cnt, 0, sizeof cnt);
    uint32_t s0[16], a[16], b[16];
    for (int ib = lo; ib < hi; ib++) {
        uint32_t *row = cnt[ib];
        for (long t = 0; t < N; t++) {
            for (int w = 0; w < 16; w++) s0[w] = (uint32_t)next64();
            if (chacha) for (int w = 0; w < 4; w++) s0[w] = SIGMA[w];
            memcpy(a, s0, sizeof a); memcpy(b, s0, sizeof b); b[ib >> 5] ^= 1u << (ib & 31);
            perm_half(a, sr, rc0, noconst); perm_half(b, sr, rc0, noconst);
            for (int w = 0; w < 16; w++) {
                uint32_t same = ~(a[w] ^ b[w]);            /* bits where the output did NOT change */
                while (same) { int lb = __builtin_ctz(same); row[w * 32 + lb]++; same &= same - 1; }
            }
        }
    }
    FILE *f = fopen(argv[4], "wb"); if (!f) { perror("fopen"); return 1; }
    fwrite(cnt, sizeof(uint32_t), 512 * 512, f); fclose(f);
    double best = 0; int bi = 0, bj = 0;
    for (int i = lo; i < hi; i++) for (int j = 0; j < 512; j++) {
        double e = fabs((double)cnt[i][j] / N - 0.5);
        if (e > best) { best = e; bi = i; bj = j; }
    }
    printf("single_rounds=%d samples=%ld seed=%llu noconst=%d ib=[%d,%d) max|eps|=%.6f (2^%.2f) at in=%d out=%d sigma=%.6f\n",
           sr, N, (unsigned long long)sd, noconst, lo, hi, best, log2(best), bi, bj, 0.5 / sqrt((double)N));
    return 0;
}
