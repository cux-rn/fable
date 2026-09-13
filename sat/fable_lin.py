"""SAT model for optimal linear trails (correlation) of the Fable Q function and Fable-P.

Modular addition z = x + y with masks (u on x, v on y, w on z) is modelled exactly via the
carry chain (Wallen 2003 / Schulte-Geers 2013): write z_i = x_i ^ y_i ^ c_i,
c_{i+1} = maj(x_i, y_i, c_i), c_0 = 0, and introduce a mask g_i on every carry bit c_i.
At bit i the local approximation  a x_i ^ b y_i ^ (g_i^w_i) c_i ^ g_{i+1} maj(x_i,y_i,c_i)
with a = u_i^w_i, b = v_i^w_i has correlation
    1           if g_{i+1} = 0 and a = b = (g_i^w_i) = 0,
    +-1/2       if g_{i+1} = 1 and a ^ b ^ (g_i^w_i) = 1,
    0           otherwise,
(bit 0 has no carry input: g_1 = 0 needs a = b = 0; g_1 = 1 is always allowed, corr +-1/2),
and g_32 = 0 (the carry out is discarded). Because at most one successor is possible from
each state the carry-mask path is unique, so |corr| = 2^-(#{i in 1..31 : g_i = 1}) exactly.
XOR: output mask copies to both inputs.  Fork (a value used twice): masks add (XOR).
Rotation: wire permutation.  Round constants do not affect linear masks (they only flip signs).
Trail correlation = 2^-W with W the sum of all addition weights; linear bias = corr / 2.

CLI:
  python sat/fable_lin.py q    --rot 16,12,8,7
  python sat/fable_lin.py perm --rounds 1 --rot 16,12,8,7 [--half] [--rate-io]
Outputs JSON to data/lin/.
"""
import argparse, json, os, sys, threading, time
from pysat.solvers import Solver
from pysat.card import ITotalizer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
QUARTERS = [(0, 4, 8, 12), (1, 5, 9, 13), (2, 6, 10, 14), (3, 7, 11, 15),
            (0, 5, 10, 15), (1, 6, 11, 12), (2, 7, 8, 13), (3, 4, 9, 14)]


class LinModel:
    def __init__(self):
        self.nv = 0
        self.clauses = []
        self.weights = []
        self.snapshots = []

    def new(self):
        self.nv += 1
        return self.nv

    def word(self):
        return [self.new() for _ in range(32)]

    @staticmethod
    def rotl(x, r):
        r %= 32
        return x[32 - r:] + x[:32 - r]

    def xor_eq(self, z, x, y):
        """constraint z = x ^ y bitwise (all three are existing literal lists)."""
        for i in range(32):
            a, b, c = x[i], y[i], z[i]
            self.clauses += [[-a, -b, -c], [a, b, -c], [a, -b, c], [-a, b, c]]

    def xor(self, x, y):
        z = self.word()
        self.xor_eq(z, x, y)
        return z

    def addlin(self, u, v, w):
        """Linear approximation (u, v -> w) of z = x + y; adds carry-mask vars g_1..g_31."""
        cl = self.clauses
        g = [None] + [self.new() for _ in range(31)] + [None]      # g[1..31]; g[0], g[32] absent (=0)
        self.weights += g[1:32]
        # bit 0: a = u0^w0, b = v0^w0; g1 = 0 -> a = b = 0
        a, b, g1 = u[0], w[0], g[1]
        # a = 0 means u0 == w0 ; encode "g1=0 -> u0==w0 and v0==w0"
        cl += [[g1, -u[0], w[0]], [g1, u[0], -w[0]], [g1, -v[0], w[0]], [g1, v[0], -w[0]]]
        for i in range(1, 32):
            gi, gn = g[i], g[i + 1]           # gn None at i = 31 (forced 0)
            ui, vi, wi = u[i], v[i], w[i]
            if gn is None:
                # g32 = 0: need u_i == w_i, v_i == w_i, g_i == w_i
                cl += [[-ui, wi], [ui, -wi], [-vi, wi], [vi, -wi], [-gi, wi], [gi, -wi]]
            else:
                # gn = 0 -> u_i == w_i, v_i == w_i, g_i == w_i
                cl += [[gn, -ui, wi], [gn, ui, -wi], [gn, -vi, wi], [gn, vi, -wi], [gn, -gi, wi], [gn, gi, -wi]]
                # gn = 1 -> (u_i^w_i) ^ (v_i^w_i) ^ (g_i^w_i) = 1  <=>  u_i ^ v_i ^ g_i ^ w_i = 1
                for bits in [(0, 0, 0, 0), (1, 1, 0, 0), (1, 0, 1, 0), (1, 0, 0, 1),
                             (0, 1, 1, 0), (0, 1, 0, 1), (0, 0, 1, 1), (1, 1, 1, 1)]:   # even parity forbidden
                    cl.append([-gn] + [-x if bit else x for x, bit in zip((ui, vi, gi, wi), bits)])

    def q(self, a, b, c, d, rot):
        """Masks on the four input wires -> masks on the four output wires."""
        r0, r1, r2, r3 = rot
        # add1: a1 = a + b.  b is also used by xor1 (b1 = b ^ c1) with mask m_b1.
        m_b1 = self.word(); v1 = self.xor(b, m_b1)                  # b = v1 ^ m_b1
        u3 = self.word(); w1 = self.xor(d, u3)                       # a1 used by xor d1 (mask d) and add3 (u3)
        self.addlin(a, v1, w1)
        m_d2 = self.rotl(d, r0)                                      # d2 = rotl(d1), mask rotates
        m_d3 = self.word(); v2 = self.xor(m_d2, m_d3)                # d2 used by add2 (v2) and xor d3 (m_d3)
        u4 = self.word(); w2 = self.xor(m_b1, u4)                    # c1 used by xor b1 (m_b1) and add4 (u4)
        self.addlin(c, v2, w2)
        m_b2 = self.rotl(m_b1, r1)
        m_b3 = self.word(); v3 = self.xor(m_b2, m_b3)                # b2 used by add3 (v3) and xor b3 (m_b3)
        out_a = self.word(); w3 = self.xor(m_d3, out_a)              # a2 used by xor d3 and output
        self.addlin(u3, v3, w3)
        m_d4 = self.rotl(m_d3, r2)
        out_d = self.word(); v4 = self.xor(m_d4, out_d)              # d4 used by add4 and output
        out_c = self.word(); w4 = self.xor(m_b3, out_c)              # c2 used by xor b3 and output
        self.addlin(u4, v4, w4)
        out_b = self.rotl(m_b3, r3)
        return out_a, out_b, out_c, out_d


def build_q(rot):
    m = LinModel()
    a, b, c, d = m.word(), m.word(), m.word(), m.word()
    m.snapshots.append(('in', [a, b, c, d]))
    m.snapshots.append(('out', list(m.q(a, b, c, d, rot))))
    return m


def build_perm(rounds, rot, extra_column=False):
    m = LinModel()
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


def restrict_rate_io(m):
    """Keystream model: input mask and output mask both confined to S[0..7]
    (an attacker of the data phase only sees / controls the rate)."""
    for ws in (m.snapshots[0][1][8:16], m.snapshots[-1][1][8:16]):
        for w in ws:
            for l in w:
                m.clauses.append([-l])


def decode(m, model):
    val = lambda v: model[v - 1] > 0
    words = lambda ws: ['%08x' % sum(int(val(w[i])) << i for i in range(32)) for w in ws]
    return {'trail': [(lab, words(ws)) for lab, ws in m.snapshots],
            'weight_check': sum(int(val(w)) for w in m.weights)}


def search(m, kmax, solver, timeout=None, kstart=0):
    inp = [l for w in m.snapshots[0][1] for l in w]
    s = Solver(name=solver, bootstrap_with=m.clauses)
    s.add_clause(inp)                                   # nonzero input mask
    tot = ITotalizer(lits=m.weights, ubound=kmax, top_id=m.nv)
    s.append_formula(tot.cnf.clauses)
    log, lb, best = [], kstart, None
    for k in range(kstart, kmax + 1):
        t0 = time.time()
        if timeout:
            timer = threading.Timer(timeout, s.interrupt); timer.start()
            res = s.solve_limited(assumptions=[-tot.rhs[k]], expect_interrupt=True)
            timer.cancel(); s.clear_interrupt()
        else:
            res = s.solve(assumptions=[-tot.rhs[k]])
        dt = time.time() - t0
        log.append({'k': k, 'result': res, 'seconds': round(dt, 2)})
        print('  k<=%d: %s (%.1fs)' % (k, {True: 'SAT', False: 'UNSAT', None: 'TIMEOUT'}[res], dt), flush=True)
        if res is True:
            best = decode(m, s.get_model()); break
        if res is None:
            break
        lb = k + 1
    return lb, best, log


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('target', choices=['q', 'perm'])
    ap.add_argument('--rounds', type=int, default=1)
    ap.add_argument('--rot', default='16,12,8,7')
    ap.add_argument('--half', action='store_true')
    ap.add_argument('--rate-io', action='store_true', help='input and output masks confined to S[0..7]')
    ap.add_argument('--kmax', type=int, default=None)
    ap.add_argument('--timeout', type=float, default=None)
    ap.add_argument('--solver', default=None)
    ap.add_argument('--out', default=None)
    ap.add_argument('--kstart', type=int, default=0, help='start at this weight (already-proven lower bound)')
    a = ap.parse_args()
    rot = tuple(int(x) for x in a.rot.split(','))
    solver = a.solver or ('glucose4' if a.timeout else 'cadical153')
    t0 = time.time()
    if a.target == 'q':
        m = build_q(rot); kmax = a.kmax or 40; name = 'lin_q_rot%s' % '_'.join(map(str, rot))
    else:
        m = build_perm(a.rounds, rot, a.half); kmax = a.kmax or 160
        name = 'lin_perm_r%d%s_rot%s' % (a.rounds, 'h' if a.half else '', '_'.join(map(str, rot)))
        if a.rate_io:
            restrict_rate_io(m); name += '_rateIO'
    print('%s: vars=%d clauses=%d weight_lits=%d' % (name, m.nv, len(m.clauses), len(m.weights)), flush=True)
    lb, best, log = search(m, kmax, solver, a.timeout, a.kstart)
    ub = best['weight_check'] if best else None
    res = {'target': a.target, 'rounds': a.rounds if a.target == 'perm' else None, 'half': a.half,
           'rate_io': a.rate_io, 'rot': rot, 'solver': solver, 'lower_bound_weight': lb,
           'best_trail_weight': ub, 'optimal': ub is not None and ub == lb, 'best_trail': best,
           'log': log, 'seconds': round(time.time() - t0, 1), 'vars': m.nv, 'clauses': len(m.clauses),
           'note': 'weight W: trail correlation = 2^-W, linear bias = 2^-(W+1)'}
    print('RESULT %s: weight >= %d, best trail weight = %s, optimal=%s (%.1fs)' % (name, lb, ub, res['optimal'], res['seconds']))
    out = a.out or os.path.join(ROOT, 'data', 'lin', name + '.json')
    os.makedirs(os.path.dirname(out), exist_ok=True)
    json.dump(res, open(out, 'w'), indent=1)
    print('wrote', out)


if __name__ == '__main__':
    main()
