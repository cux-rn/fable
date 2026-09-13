"""Empirically estimate the correlation of a linear trail JSON from fable_lin.py:
   corr = 2*Pr[ <u,x> ^ <w,P(x)> = 0 ] - 1   over random x.
Trail correlation 2^-W is the single-trail value; the measured (hull) correlation should
have |corr| close to 2^-W when one trail dominates.
Run: python sat/verify_lin.py data/lin/lin_q_rot16_12_8_7.json [--samples 1048576]
"""
import argparse, ctypes, json, os, random, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import fable

lib = ctypes.CDLL(os.path.join(ROOT, 'build', 'fable.dll' if os.name == 'nt' else 'libfable.so'))
U32x16 = ctypes.c_uint32 * 16
lib.fable_permute_rot.argtypes = [U32x16] + [ctypes.c_int] * 5


def parity(x):
    return bin(x).count('1') & 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('json')
    ap.add_argument('--samples', type=int, default=1 << 20)
    a = ap.parse_args()
    d = json.load(open(a.json))
    rot = tuple(d['rot'])
    tr = d['best_trail']['trail']
    u = [int(x, 16) for x in tr[0][1]]
    w = [int(x, 16) for x in tr[-1][1]]
    W = d['best_trail']['weight_check']
    rng = random.Random(5)
    zero = 0
    if d['target'] == 'q':
        for _ in range(a.samples):
            s = [rng.getrandbits(32) for _ in range(4)]
            pin = parity(s[0] & u[0]) ^ parity(s[1] & u[1]) ^ parity(s[2] & u[2]) ^ parity(s[3] & u[3])
            fable._q(s, 0, 1, 2, 3, rot)
            pout = parity(s[0] & w[0]) ^ parity(s[1] & w[1]) ^ parity(s[2] & w[2]) ^ parity(s[3] & w[3])
            zero += (pin ^ pout) == 0
    else:
        r = d['rounds']
        for _ in range(a.samples):
            x = [rng.getrandbits(32) for _ in range(16)]
            pin = 0
            for i in range(16): pin ^= parity(x[i] & u[i])
            s = U32x16(*x); lib.fable_permute_rot(s, r, *rot)
            pout = 0
            for i in range(16): pout ^= parity(s[i] & w[i])
            zero += (pin ^ pout) == 0
    corr = 2 * zero / a.samples - 1
    print('%s: trail weight %d (corr 2^-%d = %.3e); measured corr = %+.4e (|corr| = 2^%.2f) -> %s' % (
        os.path.basename(a.json), W, W, 2.0 ** -W, corr, __import__('math').log2(abs(corr)) if corr else float('-inf'),
        'OK' if abs(corr) >= 2.0 ** -W * 0.8 else 'MISMATCH (hull cancellation or model error)'))


if __name__ == '__main__':
    main()
