/* Fable-Stream throughput: single thread, 64 KiB chunks, >= 1 GiB input.
 * Reports GB/s (wall clock, 10^9 bytes/s and GiB/s) and cycles/byte using a dependent-add
 * chain to calibrate the core clock (same method as bench.c).
 * Usage: bench_stream [MiB (default 1024)] [chunk bytes (default 65536)] [reps (default 3)]
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#ifdef _WIN32
#include <windows.h>
#endif
#include "fable_stream_avx2.h"

static double now(void) {
#ifdef _WIN32
    LARGE_INTEGER f, c; QueryPerformanceFrequency(&f); QueryPerformanceCounter(&c);
    return (double)c.QuadPart / (double)f.QuadPart;
#else
    struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return t.tv_sec + t.tv_nsec * 1e-9;
#endif
}

static double core_ghz(void) {
    const long n = 400000000L;
    double best = 1e30;
    for (int rep = 0; rep < 3; rep++) {
        uint64_t x = 1;
        double t0 = now();
        for (long i = 0; i < n; i++) __asm__ volatile("add %1, %0" : "+r"(x) : "r"((uint64_t)i));
        double sec = now() - t0;
        (void)x;
        if (sec < best) best = sec;
    }
    return (double)n / best / 1e9;
}

typedef size_t (*fn_t)(uint8_t *, const uint8_t *, const uint8_t *, const uint8_t *, size_t, uint32_t);

static void run(const char *name, fn_t fn, uint8_t *out, const uint8_t *key, const uint8_t *nf,
                const uint8_t *data, size_t len, uint32_t chunk, int reps, double ghz) {
    double best = 1e30;
    for (int r = 0; r < reps; r++) {
        double t0 = now();
        fn(out, key, nf, data, len, chunk);
        double dt = now() - t0;
        if (dt < best) best = dt;
    }
    double bps = (double)len / best;
    printf("%-24s %8.3f s  %7.3f GB/s  %7.3f GiB/s  %6.2f cpb  (out[100]=%02x)\n",
           name, best, bps / 1e9, bps / (1024.0 * 1024 * 1024), ghz * 1e9 / bps, out[100]);
}

int main(int argc, char **argv) {
    size_t mib = argc > 1 ? (size_t)atol(argv[1]) : 1024;
    uint32_t chunk = argc > 2 ? (uint32_t)atol(argv[2]) : 65536;
    int reps = argc > 3 ? atoi(argv[3]) : 3;
#ifdef _WIN32
    SetThreadAffinityMask(GetCurrentThread(), 1);
    SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS);
#endif
    size_t len = mib << 20;
    uint8_t *data = malloc(len), *out = malloc(fable_stream_output_size(len, chunk));
    if (!data || !out) { fprintf(stderr, "alloc failed\n"); return 1; }
    uint64_t x = 0x1234567ull;
    for (size_t i = 0; i < len; i++) { x ^= x << 13; x ^= x >> 7; x ^= x << 17; data[i] = (uint8_t)x; }
    uint8_t key[32], nf[19];
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)(i * 7 + 1);
    for (int i = 0; i < 19; i++) nf[i] = (uint8_t)(200 - i);
    double ghz = core_ghz();
    printf("input %zu MiB, chunk %u, best of %d, core clock ~%.2f GHz (dependent-add calibration)\n", mib, chunk, reps, ghz);
    run("fable-stream avx2 x8", fable_stream_encrypt_x8, out, key, nf, data, len, chunk, reps, ghz);
    run("fable-stream scalar", fable_stream_encrypt_scalar, out, key, nf, data, len, chunk, reps > 1 ? 1 : 1, ghz);
    free(data); free(out);
    return 0;
}
