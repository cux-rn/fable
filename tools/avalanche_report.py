"""Aggregate raw avalanche counts (data/avalanche/av_r*.u32) into a report.

Run:  python tools/avalanche_report.py            (after c/avalanche.exe runs)
Writes data/avalanche/summary.md and prints it.
"""
import glob, os, re, sys
import numpy as np

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
D = os.path.join(ROOT, 'data', 'avalanche')
lines = []
P = lambda s='': lines.append(s)

P('# 雪崩复测汇总（C 版，rot=(16,12,8,7)）'); P()
P('| 轮数 | 样本数 | 平均翻转率 | 最大偏差 | 偏差>0.02 对数 | 偏差>0.01 对数 | 噪声 σ | 4.9σ（26 万对最大噪声期望） | 零翻转对数 |')
P('|---|---|---|---|---|---|---|---|---|')
hists = {}
tops = {}
for f in sorted(glob.glob(os.path.join(D, 'av_r*.u32'))):
    r = int(re.search(r'av_r(\d+)', f).group(1))
    txt = open(f[:-4] + '.txt').read()
    trials = int(re.search(r'trials=(\d+)', txt).group(1))
    cnt = np.fromfile(f, dtype='<u4').reshape(512, 512).astype(np.float64)
    p = cnt / trials
    dev = np.abs(p - 0.5)
    sigma = 0.5 / np.sqrt(trials)
    edges = np.arange(0, 0.105, 0.005)
    h, _ = np.histogram(dev, bins=list(edges) + [1.0])
    hists[r] = h
    idx = np.argsort(dev, axis=None)[::-1][:10]
    tops[r] = [(int(i // 512), int(i % 512), float(p.flat[i])) for i in idx]
    P('| %d | %d | %.5f | %.5f | %d | %d | %.5f | %.4f | %d |' % (
        r, trials, p.mean(), dev.max(), int((dev > 0.02).sum()), int((dev > 0.01).sum()),
        sigma, 4.9 * sigma, int((cnt == 0).sum())))
P()
P('## |p-0.5| 直方图（bin 宽 0.005，最后一列为 ≥0.10）'); P()
P('| 轮数 | ' + ' | '.join('%.3f' % e for e in np.arange(0, 0.105, 0.005)) + ' |')
P('|---|' + '---|' * 21)
for r in sorted(hists):
    P('| %d | ' % r + ' | '.join(str(int(x)) for x in hists[r]) + ' |')
P()
P('## 各轮数偏差最大的 10 个 (输入比特, 输出比特, 翻转率)'); P()
for r in sorted(tops):
    P('- 轮 %d: ' % r + ', '.join('(%d,%d,%.4f)' % t for t in tops[r]))
P()
out = '\n'.join(lines) + '\n'
open(os.path.join(D, 'summary.md'), 'w', encoding='utf-8', newline='\n').write(out)
print(out)
