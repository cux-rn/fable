#!/usr/bin/env bash
# Reproduce every number in the Fable paper / ANALYSIS-LOG.md (Appendix E of the paper).
# Requirements: clang (or gcc) with AVX2, Python 3.10+ with python-sat, numpy, cryptography, psutil, openssl.
# Long SAT searches (marked LONG) run for hours; pass --quick to skip them.
# Usage: bash reproduce.sh [--quick]
set -euo pipefail
cd "$(dirname "$0")"
QUICK=0; [ "${1:-}" = "--quick" ] && QUICK=1
CC="${CC:-clang}"
mkdir -p build data/avalanche data/diff data/dl data/lin

echo "== 1. implementations and cross-validation (paper Sec. 5.1)"
bash c/build.sh
python tests/check_c_vectors.py
python tests/check_stream_avx2.py
$CC -O3 -std=c11 -mavx2 c/test_avx2.c c/fable_p.c c/fable_p_avx2.c -o build/test_avx2.exe && ./build/test_avx2.exe

echo "== 2. avalanche (Sec. 4.1), 5e5 states per round count"
$CC -O3 -std=c11 c/avalanche.c c/fable_p.c -o build/avalanche.exe
for r in 1 2 3 4 5 6; do ./build/avalanche.exe $r 500000 $((1000+r)) data/avalanche/av_r$r.u32 > data/avalanche/av_r$r.txt; done
python tools/avalanche_report.py

echo "== 3. differential trails, exact and short (Sec. 4.2)"
python sat/fable_diff.py q    --rot 16,12,8,7
python sat/fable_diff.py perm --rounds 1 --rot 16,12,8,7
python sat/fable_diff.py perm --rounds 0 --half --rot 16,12,8,7 --rate-in
python sat/fable_diff.py perm --rounds 0 --half --rot 16,12,8,7 --rate-in --cap-out-zero
python sat/fable_diff.py perm --rounds 1 --rot 16,12,8,7 --rate-in                     # ~12 min
python sat/fable_diff.py perm --rounds 1 --rot 16,12,8,7 --rate-in --rate-out-nonzero  # ~16 min
python sat/fable_diff.py perm --rounds 1 --rot 16,12,8,7 --cap-out-zero --solver cadical153
python sat/verify_trail.py data/diff/perm_r1_rot16_12_8_7.json
python sat/verify_trail.py data/diff/perm_r1_rot16_12_8_7_rateI.json --samples 20000000
python sat/verify_trail.py data/diff/perm_r1_rot16_12_8_7_rateC0.json

echo "== 4. rotational-XOR, constants, slide, fixed points (Sec. 4.6, 4.7)"
python tools/rx_check.py
python tools/check_constants.py

echo "== 5. linear trails and hulls (Sec. 4.5)"
python sat/fable_lin.py q    --rot 16,12,8,7
python sat/fable_lin.py perm --rounds 1 --rot 16,12,8,7
python sat/verify_lin.py data/lin/lin_q_rot16_12_8_7.json
python sat/verify_lin.py data/lin/lin_perm_r1_rot16_12_8_7.json
python sat/lin_hull.py enumerate --trail data/lin/lin_perm_r1_rot16_12_8_7.json --wmax 6
python sat/lin_hull.py find --rounds 2 --fix-in data/lin/lin_perm_r1_rot16_12_8_7.json
for w in 54 58 60; do python sat/lin_hull.py enumerate --trail data/lin/lin_perm_r2_fixin.json --wmax $w --samples 0; done

echo "== 6. differential-linear biases (Sec. 4.4), 2^22 samples per bit pair"
$CC -O3 -std=c11 c/dl_bias.c c/fable_p.c -o build/dl_bias.exe
for sr in 1 2 3 4; do
  ./build/dl_bias.exe $sr 4194304 $((100+sr)) data/dl/dl_sr${sr}_const.u32   > data/dl/dl_sr${sr}_const.txt
  ./build/dl_bias.exe $sr 4194304 $((100+sr)) data/dl/dl_sr${sr}_noconst.u32 noconst > data/dl/dl_sr${sr}_noconst.txt
done
for sr in 3 4; do ./build/dl_bias.exe $sr 4194304 $((200+sr)) data/dl/dl_sr${sr}_chacha.u32 chacha 384 512 > data/dl/dl_sr${sr}_chacha.txt; done
python tools/dl_report.py

echo "== 7. performance (Sec. 5)"
$CC -O3 -std=c11 -mavx2 -DFABLE_HAVE_AVX2 c/bench.c c/fable_p.c c/fable_p_avx2.c -o build/bench.exe && ./build/bench.exe 2000000
$CC -O3 -std=c11 -mavx2 c/bench_stream.c c/fable_stream_avx2.c c/fable_p_avx2.c c/fable_p.c c/fable_aead.c -o build/bench_stream.exe && ./build/bench_stream.exe 1024 65536 3 1,4,8
python tools/bench_chacha.py 1024
python tools/bench_openssl_pinned.py 3

if [ $QUICK -eq 1 ]; then echo "--quick: skipping LONG searches"; exit 0; fi

echo "== 8. LONG: SAT lower bounds (hours each; each proven level is printed, stop when you like)"
python sat/fable_diff.py perm --rounds 2 --rot 16,12,8,7 --solver cadical153                                   # unconstrained 2 rounds
python sat/fable_diff.py perm --rounds 2 --rot 16,12,8,7 --rate-in --solver cadical153                         # rate-in 2 rounds
python sat/fable_diff.py perm --rounds 1 --rot 16,12,8,7 --rate-in --cap-out-zero --solver cadical153          # internal collision 1 round
python sat/fable_diff.py perm --rounds 2 --rot 16,12,8,7 --rate-in --cap-out-zero --solver cadical153          # internal collision 2 rounds
python sat/fable_diff.py perm --rounds 3 --rot 16,12,8,7 --rate-in --kstart 41 --solver cadical153             # rate-in 3 rounds
python sat/fable_lin.py  perm --rounds 1 --rot 16,12,8,7 --rate-io --solver cadical153                         # linear rate->rate 1 round
python sat/fable_lin.py  perm --rounds 2 --rot 16,12,8,7 --solver cadical153                                   # linear 2 rounds

echo "== 9. LONG: rotation-constant screening (Sec. 4.3)"
python sat/rot_screen_sat.py --metric q   --all --procs 8 --out data/diff/screen_q_all.csv
python sat/rot_screen_sat.py --metric r1  --all --procs 8 --kmax 10 --out data/diff/screen_r1_all.csv
python sat/rot_screen_sat.py --metric r1c --from data/diff/cands_r1c.txt --thresholds 6,9,11 --kmax 16 --procs 8 --out data/diff/screen_r1c_cands.csv
python tools/av1_tiebreak.py --from data/diff/cands_top12.txt --trials 4000 --out data/diff/av1_tiebreak_top12.csv
python sat/rot_screen_sat.py --metric r2 --from data/diff/cands_r2.txt --thresholds 16,20 --noexact --procs 8 --out data/diff/screen_r2_top.csv
python sat/rot_screen_sat.py --metric r2 --from data/diff/cands_r2.txt --thresholds 24    --noexact --procs 8 --out data/diff/screen_r2_top_k24.csv
python sat/screen_report.py data/diff/screen_r1c_cands.csv
