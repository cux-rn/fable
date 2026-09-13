/* Cross-check fable_permute_x8 (AVX2) against the scalar fable_permute on random states. */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "fable_p.h"
#include "fable_p_avx2.h"

static uint64_t x = 0x9E3779B97F4A7C15ull;
static uint32_t rnd(void) { x ^= x << 13; x ^= x >> 7; x ^= x << 17; return (uint32_t)(x >> 16); }

int main(void) {
    int bad = 0;
    for (int rounds = 1; rounds <= 12; rounds++) {
        for (int t = 0; t < 2000; t++) {
            uint32_t st[8][16], ref[8][16];
            for (int l = 0; l < 8; l++) for (int w = 0; w < 16; w++) st[l][w] = ref[l][w] = rnd();
            fable_permute_x8(st, rounds);
            for (int l = 0; l < 8; l++) fable_permute(ref[l], rounds);
            if (memcmp(st, ref, sizeof st)) { bad++; printf("mismatch rounds=%d trial=%d\n", rounds, t); break; }
        }
    }
    /* zero-state P_12 vector, lane 3 */
    uint32_t st[8][16] = {{0}};
    fable_permute_x8(st, 12);
    printf("permute12_zero lane3 word0..1 = %08x %08x (expect ab1e7e98 5cfbce32)\n", st[3][0], st[3][1]);
    printf("AVX2 vs scalar, rounds 1..12 x 2000 x 8 lanes: %s\n", bad ? "FAIL" : "OK");
    return bad != 0;
}
