"""Summarise rotation-screening CSVs produced by rot_screen_sat.py.

  python sat/screen_report.py data/diff/screen_q_all.csv
  python sat/screen_report.py data/diff/screen_r1_all.csv --top 200 --out cands.txt
Prints the weight distribution, the rank/class of (16,12,8,7), and optionally writes the
best `--top` combos (ties broken by a secondary CSV given with --tiebreak) to a file.
"""
import argparse, collections, csv, sys

BASE = (16, 12, 8, 7)


def load(path):
    rows = {}
    for r in csv.DictReader(open(path)):
        rot = tuple(int(r[k]) for k in ('r0', 'r1', 'r2', 'r3'))
        w = int(r['best_weight']) if r['best_weight'] != '' else None
        rows[rot] = (int(r['lower_bound']), w, r['optimal'] == '1')
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('csv')
    ap.add_argument('--tiebreak', default=None)
    ap.add_argument('--top', type=int, default=0)
    ap.add_argument('--out', default=None)
    ap.add_argument('--nozero', action='store_true', help='ignore combos containing rotation 0')
    a = ap.parse_args()
    rows = load(a.csv)
    if a.nozero:
        rows = {k: v for k, v in rows.items() if 0 not in k}
    print('%s: %d combos, %d optimal (lb == best)' % (a.csv, len(rows), sum(v[2] for v in rows.values())))
    dist = collections.Counter(v[1] for v in rows.values())
    print('weight distribution:', sorted(dist.items(), key=lambda x: (x[0] is None, x[0])))
    nz = {k: v for k, v in rows.items() if 0 not in k}
    dnz = collections.Counter(v[1] for v in nz.values())
    print('  excluding rotation 0:', sorted(dnz.items(), key=lambda x: (x[0] is None, x[0])), 'of', len(nz))
    if BASE in rows:
        wb = rows[BASE][1]
        better = sum(1 for v in rows.values() if v[1] is not None and v[1] > wb)
        same = dist[wb]
        print('baseline %s: weight %s; combos strictly better: %d; same class: %d; rank range %d..%d of %d'
              % (BASE, wb, better, same, better + 1, better + same, len(rows)))
    if a.top:
        tb = load(a.tiebreak) if a.tiebreak else {}
        key = lambda k: (-(rows[k][1] if rows[k][1] is not None else -1),
                         -(tb[k][1] if k in tb and tb[k][1] is not None else -1), k)
        order = sorted(rows, key=key)[:a.top]
        for k in order[:40]:
            print('  %-16s w=%s%s' % (k, rows[k][1], ('  tb=%s' % tb[k][1]) if k in tb else ''))
        if a.out:
            with open(a.out, 'w') as f:
                for k in order:
                    f.write('%d,%d,%d,%d\n' % k)
            print('wrote', a.out, len(order))


if __name__ == '__main__':
    main()
