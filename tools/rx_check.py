"""Rotational-XOR (RX) analysis of Fable-P round constants (spec v0.2 §8-6b).

Background (Khovratovich–Nikolić 2010; Ashur–Liu ToSC 2016):
  * A rotational pair (x, x<<<k) survives a modular addition with probability
      p_k = (1 + 2^(k-32) + 2^-k + 2^-32) / 4       (k=1: 2^-1.415, k=16: 2^-2.0)
    even with zero RX-difference. Fable-P has 32 additions per round, so a pure rotational
    trail already costs 32*1.415 = 45.3 bits per round for k=1.
  * XOR with a constant c turns an RX-difference d into d ^ (c ^ (c<<<k)). Constants whose
    c ^ (c<<<k) is 0 (or has low weight) do not disturb rotational trails; that is the
    weakness Ashur–Liu exploit and the reason ChaCha-without-constants would be rotational-
    friendly. The injected difference must then be paid for in the following additions
    (RX-differential of addition with difference d on one input costs about hw(d) bits
    minus at most 2 for the LSB/MSB positions, Ashur–Liu Thm. 1).

This script computes, for every k in 1..31 and every round i:
  d0 = RC[i] ^ (RC[i]<<<k)  (injected into S[0]),  d5 = (RC[i]<<<16) ^ ((RC[i]<<<16)<<<k)
their Hamming weights, and reports the per-round and 6/12-round totals of
  base cost   = 32 * (-log2 p_k)            (pure rotational cost of the additions)
  const cost  >= max(0, hw(d0)-2) + max(0, hw(d5)-2)   (crude lower bound on the extra weight)
and empirically verifies the model on one Q: measures Pr[Q(x<<<1) == Q(x)<<<1] with and
without a constant XORed into `a` before Q.
Run: python tools/rx_check.py   -> prints report, writes data/rx_check.txt
"""
import math, os, random, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from fable import RC, ROT, _rotl, _q, MASK

out = []
P = lambda *a: (out.append(' '.join(str(x) for x in a)), print(*a))
hw = lambda x: bin(x).count('1')


def rot_prob(k, n=32):
    return (1 + 2.0 ** (k - n) + 2.0 ** -k + 2.0 ** -n) / 4


def main():
    P('== rotational probability of one modular addition, p_k = (1 + 2^(k-n) + 2^-k + 2^-n)/4 ==')
    for k in (1, 2, 4, 8, 16):
        P('  k=%2d: p=%.5f = 2^%.3f ; per Fable round (32 adds): 2^%.1f ; 6 rounds: 2^%.1f ; 12 rounds: 2^%.1f' % (
            k, rot_prob(k), math.log2(rot_prob(k)), 32 * math.log2(rot_prob(k)),
            192 * math.log2(rot_prob(k)), 384 * math.log2(rot_prob(k))))
    P()
    P('== RX-difference injected by the constants per round: d0 = RC ^ (RC<<<k) into S[0], d5 for RC<<<16 into S[5] ==')
    P('  (weights hw(d0), hw(d5); crude extra-cost lower bound per round = max(0,hw(d0)-2) + max(0,hw(d5)-2))')
    for k in (1, 2, 4, 8, 16):
        row = []
        tot6 = tot12 = 0
        for i in range(12):
            c0 = RC[i]; c5 = _rotl(RC[i], 16)
            d0 = c0 ^ _rotl(c0, k); d5 = c5 ^ _rotl(c5, k)
            extra = max(0, hw(d0) - 2) + max(0, hw(d5) - 2)
            tot12 += extra
            if i >= 6: tot6 += extra
            row.append('%d/%d' % (hw(d0), hw(d5)))
        P('  k=%2d: hw(d0)/hw(d5) per round: %s' % (k, ' '.join(row)))
        P('        extra-cost lower bound: P_6 (RC[6..11]) >= %d bits, P_12 >= %d bits; '
          'zero-difference rounds: %d' % (tot6, tot12, sum(1 for i in range(12) if RC[i] ^ _rotl(RC[i], k) == 0)))
    P()
    P('== minimum over k of the injected weight (worst case for the designer) ==')
    worst = min((hw(RC[i] ^ _rotl(RC[i], k)) + hw(_rotl(RC[i], 16) ^ _rotl(_rotl(RC[i], 16), k)), k, i)
                for k in range(1, 32) for i in range(12))
    P('  min_k,i [hw(d0)+hw(d5)] = %d at k=%d, round %d' % worst)
    P()
    P('== combined RX-characteristic upper bound (independent-addition model) ==')
    for k in (1, 16):
        base6 = -192 * math.log2(rot_prob(k)); base12 = -384 * math.log2(rot_prob(k))
        ex6 = sum(max(0, hw(RC[i] ^ _rotl(RC[i], k)) - 2) + max(0, hw(_rotl(RC[i], 16) ^ _rotl(_rotl(RC[i], 16), k)) - 2) for i in range(6, 12))
        ex12 = sum(max(0, hw(RC[i] ^ _rotl(RC[i], k)) - 2) + max(0, hw(_rotl(RC[i], 16) ^ _rotl(_rotl(RC[i], 16), k)) - 2) for i in range(12))
        P('  k=%2d: P_6  RX prob <= 2^-%.1f (base %.1f + constants >= %d);  P_12 <= 2^-%.1f (base %.1f + constants >= %d)' % (
            k, base6 + ex6, base6, ex6, base12 + ex12, base12, ex12))
    P()
    P('== empirical check on one Q (k=1, 2^20 samples): Pr[Q(x<<<1) == Q(x)<<<1] ==')
    rng = random.Random(11)
    N = 1 << 20
    hit = 0
    for _ in range(N):
        x = [rng.getrandbits(32) for _ in range(4)]
        y = [_rotl(v, 1) for v in x]
        _q(x, 0, 1, 2, 3, ROT); _q(y, 0, 1, 2, 3, ROT)
        hit += y == [_rotl(v, 1) for v in x]
    P('  no constant : %d/%d = 2^%.2f  (model 4 adds: 2^%.2f)' % (hit, N, math.log2(hit / N) if hit else -99, 4 * math.log2(rot_prob(1))))
    hitc = 0
    c = RC[6]
    for _ in range(N):
        x = [rng.getrandbits(32) for _ in range(4)]
        y = [_rotl(v, 1) for v in x]
        x[0] ^= c; y[0] ^= c
        _q(x, 0, 1, 2, 3, ROT); _q(y, 0, 1, 2, 3, ROT)
        hitc += y == [_rotl(v, 1) for v in x]
    P('  with RC[6]=%08x XORed into a first (injected RX-diff hw=%d): %d/%d = %s' % (
        c, hw(c ^ _rotl(c, 1)), hitc, N, ('2^%.2f' % math.log2(hitc / N)) if hitc else '0 (below 2^-20)'))
    open(os.path.join(ROOT, 'data', 'rx_check.txt'), 'w', encoding='utf-8', newline='\n').write('\n'.join(out) + '\n')


if __name__ == '__main__':
    main()
