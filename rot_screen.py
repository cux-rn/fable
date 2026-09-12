import random, sys
sys.path.insert(0,'.')
from fable import permute
def av1(rot, trials=24, rng=None):
    tot=0
    for _ in range(trials):
        s0=[rng.getrandbits(32) for _ in range(16)]
        a=list(s0); permute(a,1,rot)
        for ib in range(0,512,4):
            s1=list(s0); s1[ib//32]^=1<<(ib%32); permute(s1,1,rot)
            tot+=sum(bin(a[w]^s1[w]).count('1') for w in range(16))
    return tot/(trials*128*512)
rng=random.Random(7)
cands=[(16,12,8,7)]
while len(cands)<150:
    c=tuple(rng.randrange(1,32) for _ in range(4))
    if c not in cands: cands.append(c)
res=sorted(((av1(c,rng=rng),c) for c in cands), reverse=True)
base=[r for r in res if r[1]==(16,12,8,7)][0]
print('rank of (16,12,8,7):', res.index(base)+1, 'of', len(res), 'score=%.4f'%base[0])
for r in res[:8]: print('%.4f'%r[0], r[1])
print('...'); 
for r in res[-3:]: print('%.4f'%r[0], r[1])
