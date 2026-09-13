"""Rotation-constant screening by exact minimum differential-trail weight (SAT).

  python sat/rot_screen_sat.py --metric r1 --all --procs 22 --out data/diff/screen_r1_all.csv
  python sat/rot_screen_sat.py --metric r2 --from cands.txt --timeout 600 --out data/diff/screen_r2_top.csv

metric: q  = single Q function (4 additions)
        r1 = one full Fable-P round (column + diagonal, 8 Q)
        r2 = two rounds (slow; use for a short list only)
Output CSV rows: r0,r1,r2,r3,lower_bound,best_weight,optimal,seconds
The file is appended to; combos already present are skipped (resumable).
"""
import argparse, csv, itertools, os, sys, time
from multiprocessing import Pool
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from fable_diff import build_q, build_perm, Searcher

METRIC = {'q': lambda rot: build_q(rot), 'r1': lambda rot: build_perm(1, rot),
          'r1c': lambda rot: build_perm(1, rot, extra_column=True),   # 1.5 rounds
          'r2': lambda rot: build_perm(2, rot)}
ARGS = {}


def _init(d):
    ARGS.update(d)


def work(rot):
    t0 = time.time()
    m = METRIC[ARGS['metric']](rot)
    solver = 'glucose4' if ARGS['timeout'] else 'cadical153'
    se = Searcher(m, ARGS['kmax'], solver)
    import io, contextlib
    with contextlib.redirect_stdout(io.StringIO()):
        stop = False
        for t in ARGS['thresholds']:            # cheap cascade: is there a trail of weight <= t ?
            res = se.solve_k(t, ARGS['timeout'])
            if res is not False:                # SAT (trail found, ub set) or timeout -> stop here
                stop = True
                break
        if not stop and not ARGS['noexact']:
            se.run(ARGS['timeout'], ARGS['total'])   # continues upward from the proven lower bound
    return (*rot, se.lb, se.ub if se.ub is not None else '', int(se.ub is not None and se.ub == se.lb),
            round(time.time() - t0, 2))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--metric', choices=list(METRIC), required=True)
    ap.add_argument('--all', action='store_true', help='all 32^4 combinations')
    ap.add_argument('--from', dest='src', help='file with one "r0,r1,r2,r3" per line')
    ap.add_argument('--limit', type=int, default=None)
    ap.add_argument('--procs', type=int, default=20)
    ap.add_argument('--kmax', type=int, default=None)
    ap.add_argument('--timeout', type=float, default=None)
    ap.add_argument('--total', type=float, default=None)
    ap.add_argument('--out', required=True)
    ap.add_argument('--thresholds', default='', help='comma list, e.g. 6,9,11: ask "weight <= t?" in order, '
                    'stop at the first SAT; combos surviving all thresholds continue to the exact search')
    ap.add_argument('--noexact', action='store_true', help='thresholds only, no exact search afterwards')
    a = ap.parse_args()
    ARGS.update(metric=a.metric, kmax=a.kmax or {'q': 40, 'r1': 64, 'r1c': 96, 'r2': 128}[a.metric],
                timeout=a.timeout, total=a.total, noexact=a.noexact,
                thresholds=[int(x) for x in a.thresholds.split(',') if x])
    if a.all:
        combos = list(itertools.product(range(32), repeat=4))
    else:
        combos = [tuple(int(x) for x in ln.replace('(', '').replace(')', '').split(',')[:4])
                  for ln in open(a.src) if ln.strip() and not ln.startswith('#')]
    done = set()
    if os.path.exists(a.out):
        for row in csv.reader(open(a.out)):
            if row and row[0] != 'r0':
                done.add(tuple(int(x) for x in row[:4]))
    todo = [c for c in combos if c not in done]
    if a.limit:
        todo = todo[:a.limit]
    print('metric=%s combos=%d done=%d todo=%d procs=%d' % (a.metric, len(combos), len(done), len(todo), a.procs), flush=True)
    new = not os.path.exists(a.out) or os.path.getsize(a.out) == 0
    f = open(a.out, 'a', newline='')
    wr = csv.writer(f)
    if new:
        wr.writerow(['r0', 'r1', 'r2', 'r3', 'lower_bound', 'best_weight', 'optimal', 'seconds'])
    t0 = time.time(); n = 0
    with Pool(a.procs, initializer=_init, initargs=(dict(ARGS),)) as pool:
        for row in pool.imap_unordered(work, todo, chunksize=8 if a.metric != 'r2' else 1):
            wr.writerow(row); n += 1
            if n % 2000 == 0 or n == len(todo):
                f.flush()
                el = time.time() - t0
                print('%d/%d  %.1fs elapsed, %.1f/s, eta %.0fs' % (n, len(todo), el, n / el, el / n * (len(todo) - n)), flush=True)
    f.close()


if __name__ == '__main__':
    main()
