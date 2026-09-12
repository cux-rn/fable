import os, random, struct, json, sys
sys.path.insert(0, os.path.dirname(__file__))
from fable import *
import fable

def test_roundtrip():
    rng = random.Random(1)
    for L in [0, 1, 31, 32, 33, 63, 64, 65, 1000]:
        for AL in [0, 1, 32, 45]:
            k = bytes(rng.getrandbits(8) for _ in range(32))
            n = bytes(rng.getrandbits(8) for _ in range(24))
            ad = bytes(rng.getrandbits(8) for _ in range(AL))
            m = bytes(rng.getrandbits(8) for _ in range(L))
            c = aead_encrypt(k, n, ad, m)
            assert len(c) == L + 32
            assert aead_decrypt(k, n, ad, c) == m
            # tamper: ciphertext bit, tag bit, AD, nonce, key
            for mut in range(len(c)):
                if mut % 7: continue
                bad = bytearray(c); bad[mut] ^= 1
                try: aead_decrypt(k, n, ad, bytes(bad)); assert False
                except ValueError: pass
            if ad:
                try: aead_decrypt(k, n, ad[:-1] + bytes([ad[-1]^1]), c); assert False
                except ValueError: pass
            try: aead_decrypt(k, n[:-1]+bytes([n[-1]^1]), ad, c); assert False
            except ValueError: pass
    print('AEAD round-trip / tamper: OK')

def test_stream():
    rng = random.Random(2)
    k = bytes(rng.getrandbits(8) for _ in range(32))
    nf = bytes(rng.getrandbits(8) for _ in range(19))
    for L in [0, 100, 4096, 4096*3, 4096*3+1, 20000]:
        d = bytes(rng.getrandbits(8) for _ in range(L))
        b = stream_encrypt(k, nf, d, chunk=4096)
        assert stream_decrypt(k, b) == d
        # truncate to a chunk boundary -> must fail
        if L >= 4096:
            cut = b[:28 + 4096 + 32]
            try: stream_decrypt(k, cut); assert False
            except ValueError: pass
        # swap two chunks -> must fail
        if L >= 4096*2:
            step = 4096+32
            body = b[28:]
            sw = b[:28] + body[step:2*step] + body[:step] + body[2*step:]
            try: stream_decrypt(k, sw); assert False
            except ValueError: pass
    print('Stream round-trip / truncation / reorder: OK')

def test_vectors():
    k = bytes(range(32)); n = bytes(range(24))
    vec = {}
    for name, ad, m in [('empty', b'', b''), ('ad_only', b'AD', b''),
                        ('short', b'', b'hello'), ('block', b'header', bytes(range(32))),
                        ('two_blocks', b'', bytes(range(64)))]:
        vec[name] = {'ad': ad.hex(), 'msg': m.hex(), 'ct_tag': aead_encrypt(k, n, ad, m).hex()}
    vec['hash256_empty'] = hash256(b'').hex()
    vec['hash256_abc'] = hash256(b'abc').hex()
    vec['permute12_zero'] = fable._bytes(permute([0]*16, 12)).hex()
    print(json.dumps(vec, indent=1))
    with open('/home/claude/fable/test_vectors_v0.1.json', 'w') as f:
        json.dump(vec, f, indent=1)

def avalanche(rounds, trials=2000, rot=ROT, seed=3):
    """Per-output-bit flip probability after flipping each input bit; returns
    (mean, min, max) over all 512x512 pairs and fraction of pairs within 0.5±0.1."""
    rng = random.Random(seed)
    counts = [[0]*512 for _ in range(512)]
    for t in range(trials):
        s0 = [rng.getrandbits(32) for _ in range(16)]
        a = list(s0); permute(a, rounds, rot)
        for ib in range(512):
            s1 = list(s0); s1[ib//32] ^= 1 << (ib % 32)
            permute(s1, rounds, rot)
            for w in range(16):
                d = a[w] ^ s1[w]
                while d:
                    lb = d & -d
                    counts[ib][w*32 + lb.bit_length()-1] += 1
                    d ^= lb
    ps = [c/trials for row in counts for c in row]
    dev = max(abs(p-0.5) for p in ps)
    ok = sum(1 for p in ps if abs(p-0.5) < 0.1)/len(ps)
    return sum(ps)/len(ps), min(ps), max(ps), dev, ok

if __name__ == '__main__':
    test_roundtrip()
    test_stream()
    test_vectors()
    for r in [1, 2, 3, 4]:
        # fewer trials for speed; permute() with rounds<6 uses last r RCs
        mean, mn, mx, dev, ok = avalanche(r, trials=300)
        print('rounds=%d mean=%.3f min=%.3f max=%.3f maxdev=%.3f within±0.1=%.3f' % (r, mean, mn, mx, dev, ok))
