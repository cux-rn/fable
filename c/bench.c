/* Cycles/byte benchmark for Fable-P (scalar) and the AVX2 8-way version.
 * Data phase absorbs 32 bytes per P_6 call, so cpb = cycles(P_6) / 32.
 * Usage: bench [iters]   (default 2e6 permutation calls per measurement)
 * Cycle source: rdtsc (TSC is invariant on modern Intel; reports TSC cycles).
 * Also prints the TSC frequency estimate so one can convert to ns.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#ifdef _WIN32
#include <windows.h>
#include <intrin.h>
#else
#include <x86intrin.h>
#endif
#include "fable_p.h"

#ifdef FABLE_HAVE_AVX2
#include "fable_p_avx2.h"
#endif

static inline uint64_t tsc(void) { return __rdtsc(); }

static double tsc_ghz(void) {
    uint64_t t0 = tsc();
    clock_t c0 = clock();
    while (clock() - c0 < CLOCKS_PER_SEC / 4) {}
    uint64_t t1 = tsc();
    return (double)(t1 - t0) / 0.25 / 1e9;
}

/* Estimate the real core clock: a chain of dependent 1-cycle adds runs at exactly 1 add/cycle. */
static double core_ghz(void) {
    const long n = 400000000L;
    double best = 1e30;
    for (int rep = 0; rep < 3; rep++) {
        uint64_t x = 1;
        uint64_t t0 = tsc();
        clock_t c0 = clock();
        for (long i = 0; i < n; i++) __asm__ volatile("add %1, %0" : "+r"(x) : "r"((uint64_t)i));
        clock_t c1 = clock();
        (void)t0; (void)x;
        double sec = (double)(c1 - c0) / CLOCKS_PER_SEC;
        if (sec < best) best = sec;
    }
    return (double)n / best / 1e9;
}

static double bench_scalar(int rounds, long iters, uint32_t *sink) {
    uint32_t s[16];
    for (int i = 0; i < 16; i++) s[i] = 0x01234567u * (i + 1);
    for (long i = 0; i < 1000; i++) fable_permute(s, rounds);      /* warm up */
    uint64_t best = UINT64_MAX;
    for (int rep = 0; rep < 5; rep++) {
        uint64_t t0 = tsc();
        for (long i = 0; i < iters; i++) fable_permute(s, rounds);  /* serial dependency chain */
        uint64_t t1 = tsc();
        if (t1 - t0 < best) best = t1 - t0;
    }
    *sink ^= s[0];
    return (double)best / iters;
}

int main(int argc, char **argv) {
    long iters = argc > 1 ? atol(argv[1]) : 2000000;
#ifdef _WIN32
    SetThreadAffinityMask(GetCurrentThread(), 1);                 /* pin to CPU 0 (a P-core) */
    SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS);
#endif
    double ghz = tsc_ghz();
    double core = core_ghz();
    double k = core / ghz;                                        /* TSC ticks -> core cycles */
    uint32_t sink = 0;
    printf("TSC ~%.2f GHz, core clock ~%.2f GHz (dependent-add chain), iters=%ld (best of 5)\n", ghz, core, iters);
    printf("cycles below are CORE cycles (TSC ticks x %.2f); cpb = cycles / 32 bytes per P_6 call\n", k);
    printf("%-22s %12s %10s %10s\n", "variant", "cycles/call", "cpb", "ns/call");
    for (int r = 6; r <= 12; r += 6) {
        double c = bench_scalar(r, iters, &sink) * k;
        printf("%-22s %12.1f %10.2f %10.1f\n", r == 6 ? "scalar P_6" : "scalar P_12", c, c / 32.0, c / core);
    }
#ifdef FABLE_HAVE_AVX2
    {
        uint32_t st[8][16];
        for (int l = 0; l < 8; l++) for (int i = 0; i < 16; i++) st[l][i] = 0x9e3779b9u * (l * 16 + i + 1);
        for (int r = 6; r <= 12; r += 6) {
            for (long i = 0; i < 1000; i++) fable_permute_x8(st, r);
            uint64_t best = UINT64_MAX;
            for (int rep = 0; rep < 5; rep++) {
                uint64_t t0 = tsc();
                for (long i = 0; i < iters / 4; i++) fable_permute_x8(st, r);
                uint64_t t1 = tsc();
                if (t1 - t0 < best) best = t1 - t0;
            }
            double c = (double)best / (iters / 4) * k;
            sink ^= st[0][0];
            printf("%-22s %12.1f %10.2f %10.1f   (8 states; per-state %.1f cycles)\n",
                   r == 6 ? "avx2 x8 P_6 +transp" : "avx2 x8 P_12 +transp", c, c / (8 * 32.0), c / core, c / 8);
        }
        /* core only: states kept in transposed layout across calls (as a Stream implementation would) */
        __m256i v[16];
        for (int w = 0; w < 16; w++) v[w] = _mm256_set1_epi32((int)(0x9e3779b9u * (w + 1)));
        for (int r = 6; r <= 12; r += 6) {
            for (long i = 0; i < 1000; i++) fable_permute_x8_t(v, r);
            uint64_t best = UINT64_MAX;
            for (int rep = 0; rep < 5; rep++) {
                uint64_t t0 = tsc();
                for (long i = 0; i < iters / 4; i++) fable_permute_x8_t(v, r);
                uint64_t t1 = tsc();
                if (t1 - t0 < best) best = t1 - t0;
            }
            double c = (double)best / (iters / 4) * k;
            sink ^= (uint32_t)_mm256_extract_epi32(v[0], 0);
            printf("%-22s %12.1f %10.2f %10.1f   (8 states; per-state %.1f cycles)\n",
                   r == 6 ? "avx2 x8 P_6 core" : "avx2 x8 P_12 core", c, c / (8 * 32.0), c / core, c / 8);
        }
    }
#endif
    printf("sink=%08x\n", sink);
    return 0;
}
