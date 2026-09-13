"""Byte-for-byte comparison of the C Fable-Stream (AVX2 x8 and scalar paths) against
fable.py stream_encrypt, plus round-trip through fable.py stream_decrypt.

Run:  bash c/build.sh && python tests/check_stream_avx2.py
"""
import ctypes, os, random, sys, time
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import fable

lib = ctypes.CDLL(os.path.join(ROOT, 'build', 'fable.dll' if os.name == 'nt' else 'libfable.so'))
for fn in ('fable_stream_encrypt_x8', 'fable_stream_encrypt_scalar'):
    getattr(lib, fn).restype = ctypes.c_size_t
    getattr(lib, fn).argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p,
                                 ctypes.c_size_t, ctypes.c_uint32]


def c_stream(fn, key, nf, data, chunk):
    n = len(data) // chunk + 1
    out = ctypes.create_string_buffer(28 + len(data) + 32 * n)
    ln = getattr(lib, fn)(out, key, nf, data, len(data), chunk)
    return out.raw[:ln]


def main():
    rng = random.Random(2026)
    key = bytes(rng.getrandbits(8) for _ in range(32))
    nf = bytes(rng.getrandbits(8) for _ in range(19))
    cases = [  # (chunk, length) -- exercise x8 groups, leftovers, empty/partial final chunk, chunk % 32 != 0
        (4096, 0), (4096, 4096 * 8), (4096, 4096 * 8 + 1), (4096, 4096 * 20 + 777), (4096, 4096 * 17),
        (1000, 1000 * 9 + 7), (32, 32 * 25 + 3), (65536, 65536 * 9 + 123), (65536, 65536 * 8),
    ]
    fails = 0
    for chunk, L in cases:
        data = bytes(rng.getrandbits(8) for _ in range(L))
        t0 = time.time(); ref = fable.stream_encrypt(key, nf, data, chunk=chunk); tp = time.time() - t0
        c8 = c_stream('fable_stream_encrypt_x8', key, nf, data, chunk)
        cs = c_stream('fable_stream_encrypt_scalar', key, nf, data, chunk)
        ok8, oks = c8 == ref, cs == ref
        dec = fable.stream_decrypt(key, c8) == data
        n = L // chunk + 1
        print('chunk=%6d len=%8d chunks=%3d (x8 groups=%d): avx2=%s scalar=%s py_decrypt(avx2)=%s  [py %.1fs]' % (
            chunk, L, n, (n - 1) // 8, ok8, oks, dec, tp))
        fails += not (ok8 and oks and dec)
        if not ok8:
            i = next(i for i in range(min(len(c8), len(ref))) if c8[i] != ref[i])
            print('   first mismatch at byte %d (chunk %d, offset %d)' % (i, (i - 28) // (chunk + 32), (i - 28) % (chunk + 32)))
    print('RESULT:', 'ALL OK' if fails == 0 else '%d FAILURES' % fails)
    sys.exit(1 if fails else 0)


if __name__ == '__main__':
    main()
