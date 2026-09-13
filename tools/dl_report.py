"""Summarise single-bit differential-linear bias measurements from c/dl_bias.exe.

  python tools/dl_report.py            (reads data/dl/dl_sr{1..4}_{const,noconst}.u32/.txt)
For every single-round count and variant: max |eps| over all 512x512 (input bit, output bit)
pairs, the top pairs, the count of pairs with |eps| > 4 sigma, and the rate-restricted maximum
(input bit in S[0..7], output bit in S[0..7], i.e. bits 0..255 on both sides).
Also compares const vs noconst pair-by-pair: max |eps_const - eps_noconst| relative to noise.
Writes data/dl/summary.md.
"""
import glob, os, re
import numpy as np

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
D = os.path.join(ROOT, 'data', 'dl')
L = []
P = lambda s='': L.append(s)


def load(sr, var):
    f = os.path.join(D, 'dl_sr%d_%s.u32' % (sr, var))
    t = os.path.join(D, 'dl_sr%d_%s.txt' % (sr, var))
    if not (os.path.exists(f) and os.path.exists(t) and os.path.getsize(t) > 0):
        return None, None
    n = int(re.search(r'samples=(\d+)', open(t).read()).group(1))
    cnt = np.fromfile(f, dtype='<u4').reshape(512, 512).astype(np.float64)
    return cnt / n - 0.5, n          # eps(i,j) = Pr[out_j unchanged] - 1/2


P('# 单比特差分-线性偏差（输入单比特差分 e_i，输出单比特掩码 e_j；eps = Pr[输出比特不变] − 1/2）'); P()
P('| 单轮数 | 变体 | 样本/对 | 噪声 σ | max\\|eps\\| 全状态 | 位置 (in,out) | max\\|eps\\| 速率→速率 | \\|eps\\|>4σ 对数 | \\|eps\\|>2^-8 对数 |')
P('|---|---|---|---|---|---|---|---|---|')
store = {}
for sr in (1, 2, 3, 4):
    for var in ('const', 'noconst', 'chacha'):
        eps, n = load(sr, var)
        if eps is None:
            continue
        lo = 384 if var == 'chacha' else 0        # chacha layout: only nonce/counter words 12..15 were flipped
        store[(sr, var)] = (eps, n)
        sig = 0.5 / np.sqrt(n)
        ae = np.abs(eps[lo:, :])
        i, j = np.unravel_index(np.argmax(ae), ae.shape)
        rr = ae[:256, :256].max() if lo == 0 else float('nan')
        P('| %d | %s | 2^%d | %.1e | %.4e (2^%.2f) | (%d,%d) | %s | %d | %d |' % (
            sr, var + (' (输入仅 S[12..15])' if lo else ''), int(np.log2(n)), sig, ae.max(), np.log2(ae.max()), i + lo, j,
            ('%.4e (2^%.2f)' % (rr, np.log2(rr))) if lo == 0 else '—',
            int((ae > 4 * sig).sum()), int((ae > 2.0 ** -8).sum())))
P()
P('## 各单轮数 |eps| 最大的 8 对（const 变体）'); P()
for sr in (1, 2, 3, 4):
    if (sr, 'const') not in store:
        continue
    eps, n = store[(sr, 'const')]
    ae = np.abs(eps)
    idx = np.argsort(ae, axis=None)[::-1][:8]
    P('- 单轮 %d: ' % sr + ', '.join('(in %d = S[%d].b%d, out %d = S[%d].b%d, eps=%+.4e)' % (
        k // 512, (k // 512) // 32, (k // 512) % 32, k % 512, (k % 512) // 32, (k % 512) % 32, eps.flat[k]) for k in idx))
P()
P('## 常量注入是否改变偏差分布（const − noconst，逐对）'); P()
P('| 单轮数 | max\\|Δeps\\| | 噪声 σ_diff=√2·σ | \\|Δeps\\|>4σ_diff 对数 | 相关系数 corr(eps_c, eps_nc) |')
P('|---|---|---|---|---|')
for sr in (1, 2, 3, 4):
    if (sr, 'const') in store and (sr, 'noconst') in store:
        ec, n = store[(sr, 'const')]; en, _ = store[(sr, 'noconst')]
        sd = np.sqrt(2) * 0.5 / np.sqrt(n)
        d = np.abs(ec - en)
        c = np.corrcoef(ec.ravel(), en.ravel())[0, 1]
        P('| %d | %.3e | %.1e | %d | %.4f |' % (sr, d.max(), sd, int((d > 4 * sd).sum()), c))
P()
txt = '\n'.join(L) + '\n'
open(os.path.join(D, 'summary.md'), 'w', encoding='utf-8', newline='\n').write(txt)
print(txt)
