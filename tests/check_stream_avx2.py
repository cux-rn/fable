"""Byte-for-byte comparison of the C Fable-Stream (AVX2 x8 and scalar paths, both parameter
sets) against fable.py stream_encrypt, plus C decrypt (x8 + scalar) round trip and tamper checks.

Run:  bash c/build.sh && python tests/check_stream_avx2.py
"""
import ctypes, os, random, sys, time
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import fable

lib = ctypes.CDLL(os.path.join(ROOT, 'build', 'fable.dll' if os.name == 'nt' else 'libfable.so'))
for fn in ('fable_stream_encrypt_x8_set', 'fable_stream_encrypt_scalar_set'):
    getattr(lib, fn).restype = ctypes.c_size_t
    getattr(lib, fn).argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p,
                                 ctypes.c_size_t, ctypes.c_uint32]
for fn in ('fable_stream_decrypt_x8_set', 'fable_stream_decrypt_scalar_set'):
    getattr(lib, fn).restype = ctypes.c_longlong
    getattr(lib, fn).argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t]
SETS = {'fable': 0, 'fable-f': 1}


def c_stream(fn, pset, key, nf, data, chunk):
    n = len(data) // chunk + 1
    out = ctypes.create_string_buffer(28 + len(data) + 32 * n)
    ln = getattr(lib, fn)(out, SETS[pset], key, nf, data, len(data), chunk)
    return out.raw[:ln]


def c_decrypt(fn, pset, key, blob):
    out = ctypes.create_string_buffer(max(1, len(blob)))
    ln = getattr(lib, fn)(out, SETS[pset], key, blob, len(blob))
    return None if ln < 0 else out.raw[:ln]


def main():
    rng = random.Random(2026)
    key = bytes(rng.getrandbits(8) for _ in range(32))
    nf = bytes(rng.getrandbits(8) for _ in range(19))
    cases = [(4096, 0), (4096, 4096 * 8), (4096, 4096 * 8 + 1), (4096, 4096 * 20 + 777), (4096, 4096 * 17),
             (1000, 1000 * 9 + 7), (32, 32 * 25 + 3), (65536, 65536 * 9 + 123), (65536, 65536 * 8)]
    fails = 0
    for pset in ('fable', 'fable-f'):
        for chunk, L in cases:
            data = bytes(rng.getrandbits(8) for _ in range(L))
            t0 = time.time(); ref = fable.stream_encrypt(key, nf, data, chunk=chunk, pset=pset); tp = time.time() - t0
            c8 = c_stream('fable_stream_encrypt_x8_set', pset, key, nf, data, chunk)
            cs = c_stream('fable_stream_encrypt_scalar_set', pset, key, nf, data, chunk)
            d8 = c_decrypt('fable_stream_decrypt_x8_set', pset, key, c8)
            ds = c_decrypt('fable_stream_decrypt_scalar_set', pset, key, c8)
            # tamper: flip one bit in a middle chunk (x8 path) and in the final tag
            bad1 = bytearray(c8); bad1[28 + (len(bad1) - 28) // 3] ^= 1
            bad2 = bytearray(c8); bad2[-1] ^= 1
            t1 = c_decrypt('fable_stream_decrypt_x8_set', pset, key, bytes(bad1)) is None
            t2 = c_decrypt('fable_stream_decrypt_x8_set', pset, key, bytes(bad2)) is None
            t3 = c_decrypt('fable_stream_decrypt_x8_set', pset, key, c8[:-40]) is None       # truncation
            wrong = c_decrypt('fable_stream_decrypt_x8_set', 'fable-f' if pset == 'fable' else 'fable', key, c8) is None
            ok = (c8 == ref, cs == ref, d8 == data, ds == data, fable.stream_decrypt(key, c8, pset=pset) == data,
                  t1, t2, t3, wrong)
            n = L // chunk + 1
            print('[%-7s] chunk=%6d len=%8d chunks=%3d: enc x8=%s scalar=%s | dec x8=%s scalar=%s py=%s | tamper=%s%s%s wrongset=%s [py %.1fs]' % (
                (pset, chunk, L, n) + tuple('Y' if x else 'N' for x in ok) + (tp,)))
            fails += not all(ok)
    print('RESULT:', 'ALL OK' if fails == 0 else '%d FAILURES' % fails)
    sys.exit(1 if fails else 0)


if __name__ == '__main__':
    main()
