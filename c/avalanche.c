/* Avalanche test for Fable-P: flip every input bit, count flips of every output bit.
 * Usage: avalanche <rounds> <trials> <seed> <out_counts.u32> [r0 r1 r2 r3]
 * Writes 512*512 uint32 counts (row = input bit, col = output bit) little-endian.
 * Prints: mean flip rate, max |p-0.5|, histogram of |p-0.5| (bin 0.005).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <math.h>
#include "fable_p.h"

static uint64_t rs[4];
static inline uint64_t rotl64(uint64_t x, int k) { return (x << k) | (x >> (64 - k)); }
static uint64_t next64(void) { /* xoshiro256** */
    uint64_t r = rotl64(rs[1] * 5, 7) * 9, t = rs[1] << 17;
    rs[2] ^= rs[0]; rs[3] ^= rs[1]; rs[1] ^= rs[2]; rs[0] ^= rs[3]; rs[2] ^= t; rs[3] = rotl64(rs[3], 45);
    return r;
}
static void seed(uint64_t s) {
    for (int i = 0; i < 4; i++) { s += 0x9E3779B97F4A7C15ull; uint64_t z = s;
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull; z = (z ^ (z >> 27)) * 0x94D049BB133111EBull; rs[i] = z ^ (z >> 31); }
}

int main(int argc, char **argv) {
    if (argc < 5) { fprintf(stderr, "usage: %s rounds trials seed out.u32 [r0 r1 r2 r3]\n", argv[0]); return 2; }
    int rounds = atoi(argv[1]); long trials = atol(argv[2]); uint64_t sd = strtoull(argv[3], 0, 10);
    int r0 = FABLE_R0, r1 = FABLE_R1, r2 = FABLE_R2, r3 = FABLE_R3;
    if (argc >= 9) { r0 = atoi(argv[5]); r1 = atoi(argv[6]); r2 = atoi(argv[7]); r3 = atoi(argv[8]); }
    seed(sd);
    static uint32_t cnt[512][512];
    memset(cnt, 0, sizeof cnt);
    uint32_t s0[16], a[16], b[16];
    for (long t = 0; t < trials; t++) {
        for (int w = 0; w < 16; w++) s0[w] = (uint32_t)next64();
        memcpy(a, s0, sizeof a); fable_permute_rot(a, rounds, r0, r1, r2, r3);
        for (int ib = 0; ib < 512; ib++) {
            memcpy(b, s0, sizeof b); b[ib >> 5] ^= 1u << (ib & 31);
            fable_permute_rot(b, rounds, r0, r1, r2, r3);
            for (int w = 0; w < 16; w++) {
                uint32_t d = a[w] ^ b[w];
                while (d) { int lb = __builtin_ctz(d); cnt[ib][w * 32 + lb]++; d &= d - 1; }
            }
        }
    }
    FILE *f = fopen(argv[4], "wb");
    if (!f) { perror("fopen"); return 1; }
    fwrite(cnt, sizeof(uint32_t), 512 * 512, f); fclose(f);

    double sum = 0, maxdev = 0; int maxi = 0, maxo = 0; long hist[21] = {0}; long zero_pairs = 0;
    for (int i = 0; i < 512; i++) for (int o = 0; o < 512; o++) {
        double p = (double)cnt[i][o] / trials, dv = fabs(p - 0.5);
        sum += p; if (dv > maxdev) { maxdev = dv; maxi = i; maxo = o; }
        if (cnt[i][o] == 0) zero_pairs++;
        int bin = (int)(dv / 0.005); if (bin > 20) bin = 20; hist[bin]++;
    }
    printf("rounds=%d trials=%ld seed=%llu rot=(%d,%d,%d,%d)\n", rounds, trials, (unsigned long long)sd, r0, r1, r2, r3);
    printf("mean_flip=%.5f max_dev=%.5f at in=%d out=%d zero_pairs=%ld sigma=%.5f\n",
           sum / (512.0 * 512), maxdev, maxi, maxo, zero_pairs, 0.5 / sqrt((double)trials));
    printf("hist |p-0.5| (bin=0.005):");
    for (int k = 0; k < 21; k++) printf(" %ld", hist[k]);
    printf("\n");
    return 0;
}
