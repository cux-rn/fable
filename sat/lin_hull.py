"""Linear hull enumeration for Fable-P (spec v0.3 §8-5b).

  python sat/lin_hull.py enumerate --trail data/lin/lin_perm_r1_rot16_12_8_7.json --wmax 6
      Fix the input and output masks to those of the given trail, enumerate ALL linear trails
      (distinct internal wire-mask assignments) with weight <= wmax, compute each trail's signed
      correlation (+-2^-w, sign from the maj/AND Walsh coefficients and from the round constants)
      and sum them: hull correlation vs. the single best trail. For 1 round the true correlation
      is also measured empirically through the C permutation.
  python sat/lin_hull.py find --rounds 2 --fix-in data/lin/lin_perm_r1_rot16_12_8_7.json
      Find a (not necessarily optimal) 2-round trail whose input mask equals the 1-round optimal
      trail's input mask, by the usual incremental search; writes a JSON usable by `enumerate`.
"""
import argparse, ctypes, json, os, random, sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pysat.solvers import Solver
from pysat.card import ITotalizer
import fable_lin
from fable_lin import LinModel, build_perm, decode

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from fable import RC, _rotl


class TracedLinModel(LinModel):
    """LinModel that records every addition's (u, v, w, g) and every word, for sign computation
    and for blocking clauses."""
    def __init__(self):
        super().__init__()
        self.adds = []
        self.all_words = []

    def word(self):
        w = super().word()
        self.all_words.append(w)
        return w

    def addlin(self, u, v, w):
        n0 = len(self.weights)
        super().addlin(u, v, w)
        g = [None] + self.weights[n0:n0 + 31] + [None]
        self.adds.append((u, v, w, g))


def build_traced(rounds, rot=(16, 12, 8, 7)):
    fable_lin.LinModel = TracedLinModel          # make build_perm use the traced model
    m = build_perm(rounds, rot)
    return m


def fix_masks(m, words, values):
    for w, val in zip(words, values):
        for i in range(32):
            m.clauses.append([w[i]] if (val >> i) & 1 else [-w[i]])


def trail_sign_and_weight(m, model, rounds):
    val = lambda v: model[v - 1] > 0
    sign, weight = 1, 0
    for (u, v, w, g) in m.adds:
        # bit 0: g1 = 1 -> AND Walsh coefficient: (a0,b0) = (1,1) gives -1/2, else +1/2
        if val(g[1]):
            weight += 1
            a0, b0 = val(u[0]) ^ val(w[0]), val(v[0]) ^ val(w[0])
            if a0 and b0:
                sign = -sign
        for i in range(1, 31):
            if val(g[i + 1]):
                weight += 1
                a, b, gw = val(u[i]) ^ val(w[i]), val(v[i]) ^ val(w[i]), val(g[i]) ^ val(w[i])
                if a + b + gw == 3:            # maj with all three variables: -1/2
                    sign = -sign
    # round constants: (-1)^<mask on S[0], RC> * (-1)^<mask on S[5], RC<<<16> at each round start
    for r in range(rounds):
        S = m.snapshots[2 * r][1]
        rc = RC[12 - rounds + r]
        m0 = sum(int(val(S[0][i])) << i for i in range(32))
        m5 = sum(int(val(S[5][i])) << i for i in range(32))
        if (bin(m0 & rc).count('1') + bin(m5 & _rotl(rc, 16)).count('1')) & 1:
            sign = -sign
    return sign, weight


def enumerate_hull(a):
    d = json.load(open(a.trail))
    rounds = d['rounds']
    tr = d['best_trail']['trail']
    u = [int(x, 16) for x in tr[0][1]]
    w = [int(x, 16) for x in tr[-1][1]]
    m = build_traced(rounds, tuple(d['rot']))
    fix_masks(m, m.snapshots[0][1], u)
    fix_masks(m, m.snapshots[-1][1], w)
    s = Solver(name='cadical153', bootstrap_with=m.clauses)
    tot = ITotalizer(lits=m.weights, ubound=a.wmax, top_id=m.nv)
    s.append_formula(tot.cnf.clauses)
    assume = [-tot.rhs[a.wmax]]
    trails, hist, total, t0 = [], {}, 0.0, time.time()
    block_vars = [l for wd in m.all_words for l in wd]
    while s.solve(assumptions=assume):
        model = s.get_model()
        sign, wt = trail_sign_and_weight(m, model, rounds)
        trails.append((sign, wt))
        hist[wt] = hist.get(wt, 0) + 1
        total += sign * 2.0 ** -wt
        s.add_clause([-l if model[l - 1] > 0 else l for l in block_vars])   # block this trail
        if len(trails) >= a.limit:
            print('  reached --limit %d, stopping enumeration' % a.limit)
            break
        if len(trails) % 1000 == 0:
            print('  %d trails so far (%.0fs)' % (len(trails), time.time() - t0), flush=True)
    best_w = min(hist) if hist else None
    pos = sum(1 for sgn, wt in trails if sgn > 0)
    print('rounds=%d in=%s out=%s' % (rounds, ' '.join('%08x' % x for x in u), ' '.join('%08x' % x for x in w)))
    print('trails with weight <= %d: %d  (by weight: %s)  positive-sign: %d, negative: %d  [%.0fs]' % (
        a.wmax, len(trails), sorted(hist.items()), pos, len(trails) - pos, time.time() - t0))
    print('single best trail: 2^-%s ; hull sum = %+.6e (|hull| = 2^%.3f)' % (
        best_w, total, __import__('math').log2(abs(total)) if total else float('-inf')))
    res = {'rounds': rounds, 'in': ['%08x' % x for x in u], 'out': ['%08x' % x for x in w], 'wmax': a.wmax,
           'n_trails': len(trails), 'by_weight': hist, 'hull_sum': total, 'best_weight': best_w,
           'signed_trails_by_weight': {str(k): [sum(1 for sg, wt in trails if wt == k and sg > 0),
                                                sum(1 for sg, wt in trails if wt == k and sg < 0)] for k in hist}}
    if rounds <= 1 and a.samples:
        lib = ctypes.CDLL(os.path.join(ROOT, 'build', 'fable.dll' if os.name == 'nt' else 'libfable.so'))
        U = ctypes.c_uint32 * 16
        lib.fable_permute_rot.argtypes = [U] + [ctypes.c_int] * 5
        rng = random.Random(7); zero = 0
        par = lambda x: bin(x).count('1') & 1
        for _ in range(a.samples):
            x = [rng.getrandbits(32) for _ in range(16)]
            pin = 0
            for i in range(16): pin ^= par(x[i] & u[i])
            st = U(*x); lib.fable_permute_rot(st, rounds, *d['rot'])
            pout = 0
            for i in range(16): pout ^= par(st[i] & w[i])
            zero += (pin ^ pout) == 0
        emp = 2 * zero / a.samples - 1
        res['empirical_corr'] = emp; res['samples'] = a.samples
        print('empirical correlation (%d samples): %+.5f  (noise sigma %.1e)' % (a.samples, emp, 1 / a.samples ** 0.5))
    out = a.out or os.path.join(ROOT, 'data', 'lin', 'hull_r%d_w%d.json' % (rounds, a.wmax))
    json.dump(res, open(out, 'w'), indent=1)
    print('wrote', out)


def find_trail(a):
    src = a.fix_in or a.fix_mid or a.fix_out
    d = json.load(open(src))
    tr = d['best_trail']['trail']
    m = build_traced(a.rounds, tuple(d['rot']))
    if a.fix_in:      # input mask of the R-round trail := input mask of the given trail
        fix_masks(m, m.snapshots[0][1], [int(x, 16) for x in tr[0][1]]); mode = 'fixin'
    elif a.fix_mid:   # mask after round 1 := input mask of the given (1-round) trail, so rounds 2.. can reuse it
        fix_masks(m, m.snapshots[2][1], [int(x, 16) for x in tr[0][1]]); mode = 'fixmid'
    else:             # output mask := output mask of the given trail
        fix_masks(m, m.snapshots[-1][1], [int(x, 16) for x in tr[-1][1]]); mode = 'fixout'
    lb, best, log = fable_lin.search(m, a.kmax, 'cadical153', None, a.kstart)
    res = {'target': 'perm', 'rounds': a.rounds, 'half': False, 'rate_io': False, 'rot': d['rot'],
           'fixed_from': src, 'mode': mode, 'lower_bound_weight_given_fix': lb,
           'best_trail_weight': best['weight_check'] if best else None, 'best_trail': best, 'log': log,
           'note': 'one mask fixed; weight is an upper bound on the unconstrained optimum'}
    out = a.out or os.path.join(ROOT, 'data', 'lin', 'lin_perm_r%d_%s.json' % (a.rounds, mode))
    json.dump(res, open(out, 'w'), indent=1)
    print('RESULT: %d-round trail with fixed input: weight %s (lower bound given this input: %d)' % (a.rounds, res['best_trail_weight'], lb))
    print('wrote', out)


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest='cmd', required=True)
    e = sub.add_parser('enumerate'); e.add_argument('--trail', required=True); e.add_argument('--wmax', type=int, required=True)
    e.add_argument('--limit', type=int, default=200000); e.add_argument('--samples', type=int, default=1 << 20); e.add_argument('--out')
    f = sub.add_parser('find'); f.add_argument('--rounds', type=int, default=2)
    f.add_argument('--fix-in'); f.add_argument('--fix-mid'); f.add_argument('--fix-out')
    f.add_argument('--kmax', type=int, default=80); f.add_argument('--kstart', type=int, default=0); f.add_argument('--out')
    a = ap.parse_args()
    (enumerate_hull if a.cmd == 'enumerate' else find_trail)(a)


if __name__ == '__main__':
    main()
