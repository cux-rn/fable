"""ChaCha20-Poly1305 reference throughput on this machine (single thread), for comparison with
Fable-Stream. Backends: `cryptography` (OpenSSL) and `pynacl` (libsodium).
The process is pinned to logical CPU 0 and raised to HIGH priority with psutil, matching the
Fable benchmarks (c/bench_stream.c). Measures (a) one 1 GiB message in a single AEAD call and
(b) 64 KiB pieces in a loop (same chunking as Fable-Stream, includes per-call overhead).
Run: python tools/bench_chacha.py [MiB=1024]
"""
import os, sys, time
try:
    import psutil
    p = psutil.Process()
    p.cpu_affinity([0])
    if os.name == 'nt':
        p.nice(psutil.HIGH_PRIORITY_CLASS)
    print('pinned to logical CPU 0, priority', p.nice())
except Exception as e:
    print('psutil pinning unavailable:', e)
MiB = int(sys.argv[1]) if len(sys.argv) > 1 else 1024
data = os.urandom(MiB << 20)
key = os.urandom(32); nonce = os.urandom(12)


def bench(name, fn, reps=3):
    best = 1e30
    for _ in range(reps):
        t0 = time.perf_counter(); fn(); dt = time.perf_counter() - t0
        best = min(best, dt)
    bps = len(data) / best
    print('%-46s %7.3f s  %6.3f GB/s  %6.3f GiB/s' % (name, best, bps / 1e9, bps / 2 ** 30), flush=True)


try:
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    import cryptography
    c = ChaCha20Poly1305(key)
    bench('cryptography %s (OpenSSL) 1 call' % cryptography.__version__, lambda: c.encrypt(nonce, data, None))
    def chunked():
        for i in range(0, len(data), 65536):
            c.encrypt(nonce, data[i:i + 65536], None)
    bench('cryptography (OpenSSL) 64 KiB chunks', chunked)
except Exception as e:
    print('cryptography unavailable:', e)
try:
    import nacl, nacl.bindings as nb
    bench('pynacl %s (libsodium) 1 call' % nacl.__version__,
          lambda: nb.crypto_aead_chacha20poly1305_ietf_encrypt(data, None, nonce, key))
except Exception as e:
    print('pynacl unavailable:', e)
