"""ChaCha20-Poly1305 reference throughput on this machine (single thread), for comparison with
Fable-Stream. Two backends: `cryptography` (OpenSSL) and `pynacl` (libsodium).
Measures (a) one 1 GiB message in a single AEAD call, and (b) 64 KiB chunks in a loop
(same chunking as Fable-Stream, includes per-call overhead).
Run: python tools/bench_chacha.py [MiB=1024]
"""
import os, sys, time
MiB = int(sys.argv[1]) if len(sys.argv) > 1 else 1024
data = os.urandom(MiB << 20)
key = os.urandom(32); nonce = os.urandom(12)
res = []


def bench(name, fn, reps=3):
    best = 1e30
    for _ in range(reps):
        t0 = time.perf_counter(); fn(); dt = time.perf_counter() - t0
        best = min(best, dt)
    bps = len(data) / best
    res.append((name, best, bps))
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
    def chunked2():
        for i in range(0, len(data), 65536):
            nb.crypto_aead_chacha20poly1305_ietf_encrypt(data[i:i + 65536], None, nonce, key)
    bench('pynacl (libsodium) 64 KiB chunks', chunked2)
    # plain ChaCha20 stream (no Poly1305) for reference
    n8 = os.urandom(8)
    bench('libsodium chacha20 stream only (no MAC)', lambda: nb.crypto_stream_chacha20_xor(data, n8, key))
except Exception as e:
    print('pynacl unavailable:', e)
