/* Fable-Stream throughput, v0.3: both parameter sets, encrypt and decrypt, AVX2 x8 and scalar,
 * single thread and multi-thread (chunk groups distributed over T threads, each thread runs the
 * same 8-way AVX2 code on its own range of chunk groups).
 * Reports wall-clock GB/s (10^9 B/s), GiB/s and cycles/byte using a dependent-add chain to
 * calibrate the core clock (single-thread numbers only).
 * Usage: bench_stream [MiB (default 1024)] [chunk (default 65536)] [reps (default 3)] [threads list e.g. 1,4,8]
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#ifdef _WIN32
#include <windows.h>
#include <process.h>
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

/* ---- multi-thread: each thread encrypts a contiguous range of full chunks ---- */
#define HDR 28
typedef struct {
    int set; const uint8_t *key, *nf, *data; uint8_t *out; uint32_t chunk;
    size_t c0, c1;            /* chunk index range [c0, c1) of full chunks */
    int decrypt;
    int cpu;                  /* logical CPU to pin the worker to (P-cores: 0,2,4,... on hybrid parts) */
} job_t;

#ifdef _WIN32
static unsigned __stdcall worker(void *arg) {
    job_t *j = (job_t *)arg;
    SetThreadAffinityMask(GetCurrentThread(), 1ull << j->cpu);
    if (j->decrypt) {
        if (fable_stream_decrypt_range_x8(j->out, j->set, j->key, j->nf, j->data, j->chunk, j->c0, j->c1) < 0) j->decrypt = -1;
    } else {
        fable_stream_encrypt_range_x8(j->out, j->set, j->key, j->nf, j->data, j->chunk, j->c0, j->c1);
    }
    return 0;
}
#endif

static double run_mt(int set, int threads, int decrypt, const uint8_t *key, const uint8_t *nf,
                     const uint8_t *data, size_t len, uint32_t chunk, uint8_t *blob, uint8_t *plain, int reps) {
    size_t nfull = len / chunk;                   /* full chunks (the final, possibly empty, chunk is done serially) */
    double best = 1e30;
    for (int r = 0; r < reps; r++) {
        double t0 = now();
        if (threads <= 1) {
            if (decrypt) fable_stream_decrypt_x8_set(plain, set, key, blob, fable_stream_output_size(len, chunk));
            else fable_stream_encrypt_x8_set(blob, set, key, nf, data, len, chunk);
        } else {
#ifdef _WIN32
            job_t jobs[64]; HANDLE th[64];
            size_t groups = nfull / 8, per = (groups + threads - 1) / threads;
            uint8_t hdr[HDR]; memcpy(hdr, "FBLS", 4); hdr[4] = 1;
            hdr[5] = (uint8_t)chunk; hdr[6] = (uint8_t)(chunk >> 8); hdr[7] = (uint8_t)(chunk >> 16); hdr[8] = (uint8_t)(chunk >> 24);
            memcpy(hdr + 9, nf, 19);
            if (!decrypt) memcpy(blob, hdr, HDR);
            int nt = 0;
            for (int t = 0; t < threads; t++) {
                size_t c0 = (size_t)t * per * 8, c1 = c0 + per * 8;
                if (c0 >= groups * 8) break;
                if (c1 > groups * 8) c1 = groups * 8;
                jobs[t] = (job_t){set, key, nf, decrypt ? blob + HDR : data, decrypt ? plain : blob + HDR, chunk, c0, c1, decrypt, 2 * t};
                th[t] = (HANDLE)_beginthreadex(NULL, 0, worker, &jobs[t], 0, NULL);
                nt++;
            }
            /* leftover full chunks (< 8) and the final chunk: serial scalar path */
            size_t body_off = groups * 8;
            for (size_t i = body_off; i < nfull + 1; i++) {
                int last = (i == nfull);
                size_t mlen = last ? len - i * (size_t)chunk : chunk;
                uint8_t nonce[24]; memcpy(nonce, nf, 19);
                nonce[19] = (uint8_t)i; nonce[20] = (uint8_t)(i >> 8); nonce[21] = (uint8_t)(i >> 16); nonce[22] = (uint8_t)(i >> 24); nonce[23] = last;
                if (decrypt) fable_aead_decrypt_set(plain + i * (size_t)chunk, set, key, nonce, hdr, HDR, blob + HDR + i * ((size_t)chunk + 32), mlen + 32);
                else fable_aead_encrypt_set(blob + HDR + i * ((size_t)chunk + 32), set, key, nonce, hdr, HDR, data + i * (size_t)chunk, mlen);
            }
            WaitForMultipleObjects(nt, th, TRUE, INFINITE);
            for (int t = 0; t < nt; t++) CloseHandle(th[t]);
#else
            fprintf(stderr, "multi-thread bench only implemented on Windows\n");
#endif
        }
        double dt = now() - t0;
        if (dt < best) best = dt;
    }
    return best;
}

int main(int argc, char **argv) {
    size_t mib = argc > 1 ? (size_t)atol(argv[1]) : 1024;
    uint32_t chunk = argc > 2 ? (uint32_t)atol(argv[2]) : 65536;
    int reps = argc > 3 ? atoi(argv[3]) : 3;
    const char *tlist = argc > 4 ? argv[4] : "1,4,8";
    size_t len = mib << 20;
    uint8_t *data = malloc(len), *blob = malloc(fable_stream_output_size(len, chunk)), *plain = malloc(len + 1);
    if (!data || !blob || !plain) { fprintf(stderr, "alloc failed\n"); return 1; }
    uint64_t x = 0x1234567ull;
    for (size_t i = 0; i < len; i++) { x ^= x << 13; x ^= x >> 7; x ^= x << 17; data[i] = (uint8_t)x; }
    uint8_t key[32], nf[19];
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)(i * 7 + 1);
    for (int i = 0; i < 19; i++) nf[i] = (uint8_t)(200 - i);
#ifdef _WIN32
    SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS);
    SetThreadAffinityMask(GetCurrentThread(), 1);
#endif
    double ghz = core_ghz();     /* main thread stays pinned to CPU 0 (a P-core) for all single-thread runs */
    printf("input %zu MiB, chunk %u, best of %d, core clock ~%.2f GHz (dependent-add calibration, used for cpb)\n", mib, chunk, reps, ghz);
    printf("%-10s %-8s %-8s %7s %9s %9s %8s %7s\n", "set", "op", "path", "threads", "seconds", "GB/s", "GiB/s", "cpb");
    for (int set = 0; set < 2; set++) {
        const char *sn = set ? "fable-f" : "fable";
        /* scalar single-thread encrypt (reference) */
        double t0 = now(); fable_stream_encrypt_scalar_set(blob, set, key, nf, data, len, chunk); double ts = now() - t0;
        printf("%-10s %-8s %-8s %7d %9.3f %9.3f %9.3f %8.2f\n", sn, "encrypt", "scalar", 1, ts, len / ts / 1e9, len / ts / 1073741824.0, ghz * 1e9 * ts / len);
        t0 = now(); fable_stream_decrypt_scalar_set(plain, set, key, blob, fable_stream_output_size(len, chunk)); double td = now() - t0;
        printf("%-10s %-8s %-8s %7d %9.3f %9.3f %9.3f %8.2f\n", sn, "decrypt", "scalar", 1, td, len / td / 1e9, len / td / 1073741824.0, ghz * 1e9 * td / len);
        char buf[64]; strncpy(buf, tlist, 63); buf[63] = 0;
        for (char *tok = strtok(buf, ","); tok; tok = strtok(NULL, ",")) {
            int th = atoi(tok);
            double te = run_mt(set, th, 0, key, nf, data, len, chunk, blob, plain, reps);
            printf("%-10s %-8s %-8s %7d %9.3f %9.3f %9.3f %8s\n", sn, "encrypt", "avx2x8", th, te, len / te / 1e9, len / te / 1073741824.0,
                   th == 1 ? (snprintf(buf + 32, 31, "%.2f", ghz * 1e9 * te / len), buf + 32) : "-");
            double tdd = run_mt(set, th, 1, key, nf, data, len, chunk, blob, plain, reps);
            int ok = memcmp(plain, data, len) == 0;
            printf("%-10s %-8s %-8s %7d %9.3f %9.3f %9.3f %8s  %s\n", sn, "decrypt", "avx2x8", th, tdd, len / tdd / 1e9, len / tdd / 1073741824.0,
                   th == 1 ? (snprintf(buf + 32, 31, "%.2f", ghz * 1e9 * tdd / len), buf + 32) : "-", ok ? "(plaintext verified)" : "(MISMATCH)");
        }
    }
    free(data); free(blob); free(plain);
    return 0;
}
