"""Tie-breaker for rotation screening: 1-round avalanche statistics (spec 7.3-1, adapted to
1 round because 2 rounds is already saturated for every candidate).

  python tools/av1_tiebreak.py --from cands.txt --trials 4000 --out data/diff/av1_tiebreak.csv
Runs build/avalanche.exe once per combo and records mean flip rate, max |p-0.5|, and the
number of (input,output) bit pairs that never flip. Higher mean / fewer zero pairs = faster
bit-level diffusion after one round.
"""
import argparse, csv, os, re, subprocess, sys, tempfile
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXE = os.path.join(ROOT, 'build', 'avalanche.exe')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--from', dest='src', required=True)
    ap.add_argument('--trials', type=int, default=4000)
    ap.add_argument('--rounds', type=int, default=1)
    ap.add_argument('--out', required=True)
    a = ap.parse_args()
    combos = [tuple(int(x) for x in ln.replace('(', '').replace(')', '').split(',')[:4])
              for ln in open(a.src) if ln.strip() and not ln.startswith('#')]
    tmp = os.path.join(tempfile.gettempdir(), 'av_tb.u32')
    with open(a.out, 'w', newline='') as f:
        wr = csv.writer(f)
        wr.writerow(['r0', 'r1', 'r2', 'r3', 'rounds', 'trials', 'mean_flip', 'max_dev', 'zero_pairs'])
        for i, c in enumerate(combos):
            o = subprocess.run([EXE, str(a.rounds), str(a.trials), '7', tmp] + [str(x) for x in c],
                               capture_output=True, text=True).stdout
            m = re.search(r'mean_flip=([\d.]+) max_dev=([\d.]+).*zero_pairs=(\d+)', o)
            wr.writerow(list(c) + [a.rounds, a.trials, m.group(1), m.group(2), m.group(3)])
            if (i + 1) % 100 == 0:
                print('%d/%d' % (i + 1, len(combos)), flush=True)
    try:
        os.remove(tmp)
    except OSError:
        pass
    print('wrote', a.out)


if __name__ == '__main__':
    main()
