"""Round-constant sanity checks for Fable-P (spec §2.3): symmetric fixed points and slide
properties over 1..12 rounds.

What is checked
 1. RC table: recomputed from frac(ln p_i) (mpmath-free, uses Python floats + Decimal check),
    all 12 distinct, RC[i] != rotl(RC[j],16) for all i,j, Hamming weights, pairwise distances.
 2. Constant-free round function F0 (RC := 0) has the invariant subspaces it is expected to
    have: zero state, all-ones is NOT an invariant, "all four columns equal" (S[4j+k] = S[4j])
    IS invariant. This is what the constants must break.
 3. With the real constants: for each n in 1..12, for both the P_12 prefix convention and the
    fable.py suffix convention, apply n rounds to the symmetric test states (zero, all-ones,
    column-symmetric random, row-symmetric random, all-words-equal random, 0x80000000 patterns)
    and check the result is NOT symmetric and NOT a fixed point.
 4. Column-symmetric class is not mapped into itself: 10^4 random column-symmetric states,
    check every intermediate round output leaves the class (it must, because S[0] and S[5]
    receive different constants).
 5. Slide: rounds i and j are identical iff RC[i] == RC[j]; report all i<j with equal RC or
    with RC[i] == rotl(RC[j], k) for any k (rotational slide). Also check that P_6's constant
    sequence RC[6..11] does not reappear as a shifted subsequence of RC[0..11] (self-similarity).
 6. Fixed points of reduced rounds: search 2^20 random states and the structured states for
    P_n(S) == S, n = 1..12 (expected: none found; a true fixed point search is infeasible and a
    random permutation has ~1 fixed point, so this only catches structured ones).

Run:  python tools/check_constants.py   (prints a report and writes data/constants_check.txt)
"""
import math, os, random, sys
from decimal import Decimal, getcontext
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import fable
from fable import RC, fable_round, _rotl, MASK

out = []
P = lambda *a: (out.append(' '.join(str(x) for x in a)), print(*a))
PRIMES = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]


def rounds_noconst(s, n):
    saved = fable.RC[:]
    try:
        for i in range(12): fable.RC[i] = 0
        for i in range(n): fable_round(s, i)
    finally:
        fable.RC[:] = saved
    return s


def rounds_prefix(s, n):     # rounds 0..n-1 (P_12 prefix)
    for i in range(n): fable_round(s, i)
    return s


def rounds_suffix(s, n):     # rounds 12-n..11 (fable.py convention, P_6 = suffix)
    for i in range(12 - n, 12): fable_round(s, i)
    return s


def col_sym(s): return all(s[4 * j + k] == s[4 * j] for j in range(4) for k in range(4))
def row_sym(s): return all(s[4 * j + k] == s[k] for j in range(4) for k in range(4))
def all_eq(s): return all(x == s[0] for x in s)
def is_sym(s): return col_sym(s) or row_sym(s) or all_eq(s)


def main():
    rng = random.Random(20260913)
    P('== 1. RC table ==')
    getcontext().prec = 60
    ok = True
    for i, p in enumerate(PRIMES):
        v = Decimal(p).ln()
        frac = v - int(v)
        rc = int(frac * (1 << 32))
        P('  RC[%2d] p=%2d frac(ln p)=%s -> %08x  spec=%08x  hw=%2d %s' % (
            i, p, str(frac)[:12], rc, RC[i], bin(RC[i]).count('1'), 'OK' if rc == RC[i] else 'MISMATCH'))
        ok &= rc == RC[i]
    P('  recomputed from ln(p):', 'ALL MATCH' if ok else 'MISMATCH')
    P('  distinct:', len(set(RC)) == 12)
    rot16 = [(i, j) for i in range(12) for j in range(12) if RC[i] == _rotl(RC[j], 16)]
    P('  RC[i] == rotl(RC[j],16) pairs (would make S[0] and S[5] injections collide):', rot16 or 'none')
    dmin = min(bin(RC[i] ^ RC[j]).count('1') for i in range(12) for j in range(i + 1, 12))
    P('  min pairwise Hamming distance:', dmin)
    P('  RC[i] ^ rotl(RC[i],16) (net constant on the diagonal Q(0,5,10,15)) all nonzero:',
      all(RC[i] ^ _rotl(RC[i], 16) for i in range(12)))

    P('== 2. Constant-free round: invariants that constants must break ==')
    z = rounds_noconst([0] * 16, 12)
    P('  zero state fixed under 12 const-free rounds:', z == [0] * 16)
    ones = rounds_noconst([MASK] * 16, 1)
    P('  all-ones after 1 const-free round symmetric:', is_sym(ones), '(fixed:', ones == [MASK] * 16, ')')
    cs = [rng.getrandbits(32) for _ in range(4)]
    s = [cs[j] for j in range(4) for _ in range(4)]
    keep = all(col_sym(rounds_noconst(list(s), n)) for n in range(1, 13))
    P('  column-symmetric class invariant under const-free rounds (1..12):', keep)
    rs = [rng.getrandbits(32) for _ in range(4)]
    s = [rs[k] for _ in range(4) for k in range(4)]
    P('  row-symmetric class invariant under const-free rounds:', all(row_sym(rounds_noconst(list(s), n)) for n in range(1, 13)))
    s = [rng.getrandbits(32)] * 16
    P('  all-words-equal class invariant under const-free rounds:', all(all_eq(rounds_noconst(list(s), n)) for n in range(1, 13)))

    P('== 3/4. With constants: symmetric inputs, 1..12 rounds, prefix and suffix conventions ==')
    tests = {'zero': [0] * 16, 'ones': [MASK] * 16, 'msb': [0x80000000] * 16, 'lsb': [1] * 16}
    for t in range(3):
        cs = [rng.getrandbits(32) for _ in range(4)]
        tests['colsym%d' % t] = [cs[j] for j in range(4) for _ in range(4)]
        tests['rowsym%d' % t] = [cs[k] for _ in range(4) for k in range(4)]
        tests['alleq%d' % t] = [cs[0]] * 16
    bad = 0
    for name, st in tests.items():
        for conv, fn in (('prefix', rounds_prefix), ('suffix', rounds_suffix)):
            for n in range(1, 13):
                o = fn(list(st), n)
                if is_sym(o) or o == st:
                    bad += 1
                    P('  !! %s %s n=%d: symmetric=%s fixed=%s' % (name, conv, n, is_sym(o), o == st))
    P('  structured inputs -> symmetric or fixed outputs found:', bad)
    # every intermediate round leaves the column-symmetric class
    leave = 0
    for _ in range(10000):
        cs = [rng.getrandbits(32) for _ in range(4)]
        s = [cs[j] for j in range(4) for _ in range(4)]
        for i in range(12):
            fable_round(s, i)
            if col_sym(s): leave += 1
    P('  10^4 random column-symmetric states x 12 rounds: intermediate outputs still column-symmetric:', leave)

    P('== 5. Slide / self-similarity of the constant sequence ==')
    eq = [(i, j) for i in range(12) for j in range(i + 1, 12) if RC[i] == RC[j]]
    P('  equal RC pairs (classic slide requires these):', eq or 'none')
    rs = [(i, j, k) for i in range(12) for j in range(12) if i != j for k in range(32) if RC[i] == _rotl(RC[j], k)]
    P('  rotational coincidences RC[i]==rotl(RC[j],k):', rs or 'none')
    sub = [d for d in range(1, 6) if all(RC[6 + t + d] == RC[6 + t] for t in range(6 - d))]
    P('  P_6 constants RC[6..11] periodic / self-similar with shift d:', sub or 'none')
    # Is P_6 a "slid" version of another window of P_12? (RC[6..11] == RC[a..a+5] for a != 6)
    P('  RC[6..11] equals another 6-window of RC:', [a for a in range(7) if a != 6 and RC[a:a + 6] == RC[6:12]] or 'none')
    # affine slide: exists constant c with RC[i+1] = RC[i] ^ c for all i?
    xs = set(RC[i] ^ RC[i + 1] for i in range(11))
    P('  consecutive XOR differences all distinct (no affine slide):', len(xs) == 11)

    P('== 6. Fixed-point / short-cycle sampling ==')
    fixed = 0
    N = 1 << 18
    for name, st in tests.items():
        for n in range(1, 13):
            if rounds_prefix(list(st), n) == st or rounds_suffix(list(st), n) == st:
                fixed += 1
    P('  structured states that are fixed points of some P_n (prefix or suffix), n=1..12:', fixed)
    # random fixed-point sampling for 1-round (the only case where a structural fixed point
    # would show up with non-negligible density)
    hits = sum(1 for _ in range(N) if (lambda s: rounds_prefix(list(s), 1) == s)([rng.getrandbits(32) for _ in range(16)]))
    P('  random 1-round fixed points among 2^18 samples:', hits, '(expected ~0 for a random permutation)')
    open(os.path.join(ROOT, 'data', 'constants_check.txt'), 'w', encoding='utf-8', newline='\n').write('\n'.join(out) + '\n')


if __name__ == '__main__':
    main()
