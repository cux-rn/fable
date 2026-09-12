"""Check the C implementation (build/fable.dll) against test_vectors_v0.1.json and
against the Python reference on random inputs.

Run:  bash c/build.sh && python tests/check_c_vectors.py
"""
import ctypes, json, os, random, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import fable  # Python reference

libname = 'fable.dll' if os.name == 'nt' else 'libfable.so'
lib = ctypes.CDLL(os.path.join(ROOT, 'build', libname))
U32x16 = ctypes.c_uint32 * 16
lib.fable_permute.argtypes = [U32x16, ctypes.c_int]
lib.fable_permute_rot.argtypes = [U32x16] + [ctypes.c_int] * 5
lib.fable_aead_encrypt.restype = ctypes.c_size_t
lib.fable_aead_encrypt.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p,
                                   ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p, ctypes.c_size_t]
lib.fable_aead_decrypt.restype = ctypes.c_int
lib.fable_aead_decrypt.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p,
                                   ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p, ctypes.c_size_t]
lib.fable_xof.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p, ctypes.c_size_t]


def c_permute(words, rounds, rot=None):
    st = U32x16(*words)
    if rot is None:
        lib.fable_permute(st, rounds)
    else:
        lib.fable_permute_rot(st, rounds, *rot)
    return list(st)


def c_encrypt(k, n, ad, m):
    out = ctypes.create_string_buffer(len(m) + 32)
    ln = lib.fable_aead_encrypt(out, k, n, ad, len(ad), m, len(m))
    return out.raw[:ln]


def c_decrypt(k, n, ad, c):
    out = ctypes.create_string_buffer(max(1, len(c) - 32))
    r = lib.fable_aead_decrypt(out, k, n, ad, len(ad), c, len(c))
    return None if r else out.raw[:len(c) - 32]


def c_hash256(data):
    out = ctypes.create_string_buffer(32)
    lib.fable_xof(out, 32, data, len(data))
    return out.raw


def main():
    vec = json.load(open(os.path.join(ROOT, 'test_vectors_v0.1.json')))
    fails = 0
    # 1. permute12_zero
    got = fable._bytes(c_permute([0] * 16, 12)).hex()
    ok = got == vec['permute12_zero']
    print('permute12_zero:', 'OK' if ok else 'FAIL'); fails += not ok
    # 2. AEAD vectors
    k = bytes(range(32)); n = bytes(range(24))
    for name in ['empty', 'ad_only', 'short', 'block', 'two_blocks']:
        v = vec[name]
        ad, m = bytes.fromhex(v['ad']), bytes.fromhex(v['msg'])
        ct = c_encrypt(k, n, ad, m)
        ok = ct.hex() == v['ct_tag']
        ok2 = c_decrypt(k, n, ad, ct) == m
        bad = bytearray(ct); bad[-1] ^= 1
        ok3 = c_decrypt(k, n, ad, bytes(bad)) is None
        print('aead %-10s enc=%s dec=%s tamper=%s' % (name, ok, ok2, ok3))
        fails += not (ok and ok2 and ok3)
    # 3. hash vectors
    for name, data in [('hash256_empty', b''), ('hash256_abc', b'abc')]:
        ok = c_hash256(data).hex() == vec[name]
        print('%s: %s' % (name, 'OK' if ok else 'FAIL')); fails += not ok
    # 4. random cross-check vs Python: permutation for every round count 1..12
    rng = random.Random(2026)
    for r in range(1, 13):
        for _ in range(50):
            s = [rng.getrandbits(32) for _ in range(16)]
            if fable.permute(list(s), r) != c_permute(s, r):
                print('permute mismatch rounds=%d' % r); fails += 1; break
    # rotation variant
    for _ in range(200):
        rot = tuple(rng.randrange(0, 32) for _ in range(4))
        s = [rng.getrandbits(32) for _ in range(16)]
        if fable.permute(list(s), 6, rot) != c_permute(s, 6, rot):
            print('permute_rot mismatch', rot); fails += 1; break
    print('permute cross-check (rounds 1..12, random rot): OK' if not fails else '')
    # random AEAD cross-check
    for L in [0, 1, 31, 32, 33, 63, 64, 65, 1000]:
        for AL in [0, 1, 32, 45]:
            kk = bytes(rng.getrandbits(8) for _ in range(32))
            nn = bytes(rng.getrandbits(8) for _ in range(24))
            ad = bytes(rng.getrandbits(8) for _ in range(AL))
            m = bytes(rng.getrandbits(8) for _ in range(L))
            ct = c_encrypt(kk, nn, ad, m)
            if ct != fable.aead_encrypt(kk, nn, ad, m) or c_decrypt(kk, nn, ad, ct) != m:
                print('AEAD mismatch L=%d AL=%d' % (L, AL)); fails += 1
    print('AEAD random cross-check vs fable.py: OK' if not fails else '')
    print('RESULT:', 'ALL OK' if fails == 0 else '%d FAILURES' % fails)
    sys.exit(1 if fails else 0)


if __name__ == '__main__':
    main()
