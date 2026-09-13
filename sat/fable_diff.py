"""SAT model for optimal XOR-differential characteristics of the Fable Q function and Fable-P.

Modular addition is modelled with the Lipmaa-Moriai conditions (exact xdp+):
  z = x + y with differences (a, b -> c) is valid iff
     a0 ^ b0 ^ c0 = 0  and  for i in 0..30:  (a_i = b_i = c_i)  =>  a_{i+1}^b_{i+1}^c_{i+1} = a_i
  weight = #{ i in 0..30 : not (a_i = b_i = c_i) },  probability = 2^-weight.
XOR is linear on differences; rotation is a wire permutation; round constants vanish.
Total weight is bounded with an incremental totalizer (pysat ITotalizer); the minimum
weight W is proved by UNSAT at W-1 and a satisfying trail at W.

CLI examples:
  python sat/fable_diff.py q    --rot 16,12,8,7
  python sat/fable_diff.py perm --rounds 2 --rot 16,12,8,7 --timeout 3600
Outputs JSON (trail + bounds + timings) to data/diff/ unless --out is given.
"""
import argparse, itertools, json, os, sys, threading, time
from pysat.solvers import Solver
from pysat.card import ITotalizer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
QUARTERS = [(0, 4, 8, 12), (1, 5, 9, 13), (2, 6, 10, 14), (3, 7, 11, 15),
            (0, 5, 10, 15), (1, 6, 11, 12), (2, 7, 8, 13), (3, 4, 9, 14)]
ODD4 = [bits for bits in itertools.product([0, 1], repeat=4) if sum(bits) % 2 == 1]
ODD3 = [bits for bits in itertools.product([0, 1], repeat=3) if sum(bits) % 2 == 1]


class Model:
    def __init__(self):
        self.nv = 0
        self.clauses = []
        self.weights = []      # one literal per (addition, bit 0..30): 1 = costs a factor 1/2
        self.snapshots = []    # (label, [16 words]) for trail printing

    def new(self):
        self.nv += 1
        return self.nv

    def word(self):
        return [self.new() for _ in range(32)]

    @staticmethod
    def rotl(x, r):
        r %= 32
        return x[32 - r:] + x[:32 - r]       # new bit i = old bit (i - r) mod 32

    def xor(self, x, y):
        z = self.word()
        cl = self.clauses
        for i in range(32):
            a, b, c = x[i], y[i], z[i]
            cl += [[-a, -b, -c], [a, b, -c], [a, -b, c], [-a, b, c]]
        return z

    def add(self, x, y):
        """Differential propagation through z = x + y (mod 2^32)."""
        z = self.word()
        cl = self.clauses
        a, b, c = x[0], y[0], z[0]
        for bits in ODD3:                                   # a0 ^ b0 ^ c0 = 0
            cl.append([-v if bit else v for v, bit in zip((a, b, c), bits)])
        for i in range(31):
            a, b, c = x[i], y[i], z[i]
            a1, b1, c1 = x[i + 1], y[i + 1], z[i + 1]
            w = self.new()
            self.weights.append(w)
            cl += [[w, -a, b], [w, a, -b], [w, -b, c], [w, b, -c]]     # ~w -> a=b=c
            cl += [[-w, -a, -b, -c], [-w, a, b, c]]                     # w -> not(a=b=c)
            for bits in ODD4:                                           # ~w -> a1^b1^c1^a = 0
                cl.append([w] + [-v if bit else v for v, bit in zip((a1, b1, c1, a), bits)])
        return z

    def q(self, a, b, c, d, rot):
        r0, r1, r2, r3 = rot
        a = self.add(a, b); d = self.rotl(self.xor(d, a), r0)
        c = self.add(c, d); b = self.rotl(self.xor(b, c), r1)
        a = self.add(a, b); d = self.rotl(self.xor(d, a), r2)
        c = self.add(c, d); b = self.rotl(self.xor(b, c), r3)
        return a, b, c, d


def build_q(rot):
    m = Model()
    a, b, c, d = m.word(), m.word(), m.word(), m.word()
    m.snapshots.append(('in', [a, b, c, d]))
    m.snapshots.append(('out', list(m.q(a, b, c, d, rot))))
    return m


def build_perm(rounds, rot, extra_column=False):
    """`rounds` full rounds; with extra_column=True one more column step is appended
    (a "rounds + 0.5" model, used as a tie-breaker in rotation screening)."""
    m = Model()
    S = [m.word() for _ in range(16)]
    m.snapshots.append(('in', list(S)))
    for r in range(rounds):
        for (a, b, c, d) in QUARTERS[:4]:
            S[a], S[b], S[c], S[d] = m.q(S[a], S[b], S[c], S[d], rot)
        m.snapshots.append(('r%d_col' % (r + 1), list(S)))
        for (a, b, c, d) in QUARTERS[4:]:
            S[a], S[b], S[c], S[d] = m.q(S[a], S[b], S[c], S[d], rot)
        m.snapshots.append(('r%d_out' % (r + 1), list(S)))
    if extra_column:
        for (a, b, c, d) in QUARTERS[:4]:
            S[a], S[b], S[c], S[d] = m.q(S[a], S[b], S[c], S[d], rot)
        m.snapshots.append(('r%d_col' % (rounds + 1), list(S)))
    return m


def decode(m, model):
    val = lambda v: model[v - 1] > 0
    words = lambda ws: ['%08x' % sum(int(val(w[i])) << i for i in range(32)) for w in ws]
    return {'trail': [(lab, words(ws)) for lab, ws in m.snapshots],
            'weight_check': sum(int(val(w)) for w in m.weights)}


def restrict_rate(m, rate_in=True, cap_out_zero=False, rate_out_nonzero=False):
    """Keyed-duplex data-phase model (spec v0.2 §2.4 / §8-4b):
      rate_in         : input difference only in S[0..7]; S[8..15] input difference = 0
      cap_out_zero    : output difference in S[8..15] = 0 (internal-collision / forgery model)
      rate_out_nonzero: output difference in S[0..7] != 0 (observable in the keystream)
    Adds unit clauses / one big clause to m.clauses; the nonzero-input clause added by
    Searcher then effectively ranges over S[0..7] only."""
    inp = m.snapshots[0][1]
    out = m.snapshots[-1][1]
    if rate_in:
        for w in inp[8:16]:
            for l in w:
                m.clauses.append([-l])
    if cap_out_zero:
        for w in out[8:16]:
            for l in w:
                m.clauses.append([-l])
    if rate_out_nonzero:
        m.clauses.append([l for w in out[0:8] for l in w])


class Searcher:
    """Incremental min-weight search. lb = proven lower bound (weight >= lb),
    ub = weight of best trail found (None if none)."""

    def __init__(self, m, kmax, solver='cadical153'):
        self.m = m
        inp = [l for w in m.snapshots[0][1] for l in w]
        self.s = Solver(name=solver, bootstrap_with=m.clauses)
        self.s.add_clause(inp)                        # nonzero input difference
        self.tot = ITotalizer(lits=m.weights, ubound=kmax, top_id=m.nv)
        self.s.append_formula(self.tot.cnf.clauses)
        self.kmax = kmax
        self.lb, self.ub, self.best = 0, None, None
        self.log = []

    def solve_k(self, k, timeout=None):
        """SAT: trail with weight <= k exists. Returns True/False/None(timeout)."""
        t0 = time.time()
        if timeout:
            timer = threading.Timer(timeout, self.s.interrupt)
            timer.start()
            res = self.s.solve_limited(assumptions=[-self.tot.rhs[k]], expect_interrupt=True)
            timer.cancel()
            self.s.clear_interrupt()
        else:
            res = self.s.solve(assumptions=[-self.tot.rhs[k]])
        dt = time.time() - t0
        self.log.append({'k': k, 'result': res, 'seconds': round(dt, 2)})
        print('  k<=%d: %s (%.1fs)' % (k, {True: 'SAT', False: 'UNSAT', None: 'TIMEOUT'}[res], dt), flush=True)
        if res is True:
            if self.ub is None or k < self.ub:
                self.ub = k
                self.best = decode(self.m, self.s.get_model())
                self.ub = self.best['weight_check']
        elif res is False:
            self.lb = max(self.lb, k + 1)
        return res

    def run(self, timeout_per_k=None, total_timeout=None):
        """Increase k from lb until SAT. On timeout, look for an upper bound with big jumps."""
        t_start = time.time()
        k = self.lb
        while k <= self.kmax:
            res = self.solve_k(k, timeout_per_k)
            if res is True:
                return
            if res is None:
                break
            k += 1
            if total_timeout and time.time() - t_start > total_timeout:
                break
        # Upper-bound phase: jump up, then tighten downward while time allows.
        jump = 8
        k = self.lb + jump
        while self.ub is None and k <= self.kmax:
            res = self.solve_k(k, timeout_per_k)
            if res is False:
                self.lb = k + 1
            elif res is None:
                jump *= 2
            k = max(k, self.lb) + jump
        # tighten: binary-ish search between lb and ub
        while self.ub is not None and self.ub - 1 >= self.lb:
            if total_timeout and time.time() - t_start > total_timeout:
                break
            k = (self.lb + self.ub - 1) // 2
            res = self.solve_k(k, timeout_per_k)
            if res is None:
                k = self.ub - 1
                if k < self.lb:
                    break
                res = self.solve_k(k, timeout_per_k)
                if res is None:
                    break


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('target', choices=['q', 'perm'])
    ap.add_argument('--rounds', type=int, default=1)
    ap.add_argument('--rot', default='16,12,8,7')
    ap.add_argument('--kmax', type=int, default=None)
    ap.add_argument('--timeout', type=float, default=None, help='seconds per SAT call')
    ap.add_argument('--total', type=float, default=None, help='total seconds budget')
    ap.add_argument('--out', default=None)
    ap.add_argument('--solver', default=None,
                    help='pysat solver name; default cadical153, or glucose4 when --timeout is set '
                         '(CaDiCaL cannot be interrupted in pysat)')
    ap.add_argument('--rate-in', action='store_true', help='input difference restricted to S[0..7]')
    ap.add_argument('--cap-out-zero', action='store_true', help='output difference in S[8..15] must be 0')
    ap.add_argument('--rate-out-nonzero', action='store_true', help='output difference in S[0..7] must be nonzero')
    ap.add_argument('--half', action='store_true', help='append one extra column step (rounds + 0.5)')
    a = ap.parse_args()
    rot = tuple(int(x) for x in a.rot.split(','))
    solver = a.solver or ('glucose4' if a.timeout else 'cadical153')
    t0 = time.time()
    if a.target == 'q':
        m = build_q(rot); kmax = a.kmax or 40; name = 'q_rot%s' % '_'.join(map(str, rot))
    else:
        m = build_perm(a.rounds, rot, extra_column=a.half); kmax = a.kmax or 160
        name = 'perm_r%d%s_rot%s' % (a.rounds, 'h' if a.half else '', '_'.join(map(str, rot)))
        if a.rate_in or a.cap_out_zero or a.rate_out_nonzero:
            restrict_rate(m, a.rate_in, a.cap_out_zero, a.rate_out_nonzero)
            name += '_rate' + ('I' if a.rate_in else '') + ('C0' if a.cap_out_zero else '') + ('O' if a.rate_out_nonzero else '')
    print('%s: vars=%d clauses=%d weight_lits=%d' % (name, m.nv, len(m.clauses), len(m.weights)), flush=True)
    se = Searcher(m, kmax, solver)
    se.run(a.timeout, a.total)
    res = {'target': a.target, 'rounds': a.rounds if a.target == 'perm' else None, 'rot': rot,
           'solver': solver, 'half': a.half,
           'restrict': {'rate_in': a.rate_in, 'cap_out_zero': a.cap_out_zero, 'rate_out_nonzero': a.rate_out_nonzero},
           'lower_bound_weight': se.lb, 'best_trail_weight': se.ub,
           'optimal': se.ub is not None and se.ub == se.lb,
           'best_trail': se.best, 'log': se.log, 'seconds': round(time.time() - t0, 1),
           'vars': m.nv, 'clauses': len(m.clauses)}
    print('RESULT %s: weight >= %d, best trail weight = %s, optimal=%s (%.1fs)' % (
        name, se.lb, se.ub, res['optimal'], res['seconds']))
    out = a.out or os.path.join(ROOT, 'data', 'diff', name + '.json')
    os.makedirs(os.path.dirname(out), exist_ok=True)
    json.dump(res, open(out, 'w'), indent=1)
    print('wrote', out)


if __name__ == '__main__':
    main()
