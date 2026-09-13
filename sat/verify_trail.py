"""Empirically verify a differential trail JSON produced by fable_diff.py.

Samples random inputs, applies the input difference, runs the C permutation (or a
Python Q) and counts how often the output difference of the best trail appears.
The characteristic probability 2^-w is a lower bound on the differential probability,
so the observed rate should be >= 2^-w (clustering can only raise it).

Run:  python sat/verify_trail.py data/diff/perm_r1_rot16_12_8_7.json [--samples 2000000]
"""
import argparse, ctypes, json, os, random, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import fable

lib = ctypes.CDLL(os.path.join(ROOT, 'build', 'fable.dll' if os.name == 'nt' else 'libfable.so'))
U32x16 = ctypes.c_uint32 * 16
lib.fable_permute_rot.argtypes = [U32x16] + [ctypes.c_int] * 5


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('json')
    ap.add_argument('--samples', type=int, default=1 << 20)
    a = ap.parse_args()
    d = json.load(open(a.json))
    rot = tuple(d['rot'])
    tr = d['best_trail']['trail']
    din = [int(x, 16) for x in tr[0][1]]
    dout = [int(x, 16) for x in tr[-1][1]]
    w = d['best_trail']['weight_check']
    rng = random.Random(1)
    hits = 0
    if d['target'] == 'q':
        for _ in range(a.samples):
            s = [rng.getrandbits(32) for _ in range(4)]
            t = [s[i] ^ din[i] for i in range(4)]
            fable._q(s, 0, 1, 2, 3, rot); fable._q(t, 0, 1, 2, 3, rot)
            hits += all(s[i] ^ t[i] == dout[i] for i in range(4))
    else:
        r = d['rounds']
        for _ in range(a.samples):
            s = U32x16(*[rng.getrandbits(32) for _ in range(16)])
            t = U32x16(*[s[i] ^ din[i] for i in range(16)])
            lib.fable_permute_rot(s, r, *rot); lib.fable_permute_rot(t, r, *rot)
            hits += all(s[i] ^ t[i] == dout[i] for i in range(16))
    p = hits / a.samples
    print('%s: trail weight %d (2^-%d = %.3e); observed %d/%d = %.3e  -> %s' % (
        os.path.basename(a.json), w, w, 2.0 ** -w, hits, a.samples, p,
        'OK (observed >= predicted)' if p >= 2.0 ** -w * 0.8 else 'MISMATCH'))


if __name__ == '__main__':
    main()
