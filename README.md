# Fable v0.1（研究草案）

**未经公开密码分析，禁止用于任何真实数据。**

- `Fable-spec-v0.1.md` — 设计规范
- `fable.py` — Python 参考实现
- `test_fable.py` — 功能测试、测试向量生成、雪崩测试
- `rot_screen.py` — 旋转常数粗筛脚本
- `test_vectors_v0.1.json` — 测试向量
- `ANALYSIS-LOG.md` — 分析记录与待办
- `c/` — C 实现（`fable_p.c` 置换、`fable_aead.c` AEAD/XOF、`fable_p_avx2.c` 8 路 AVX2、`avalanche.c`、`bench.c`），`bash c/build.sh` 构建 DLL
- `tests/check_c_vectors.py` — C 版与测试向量 / Python 参考交叉校验
- `sat/` — python-sat 差分特征模型（`fable_diff.py`，含速率受限开关）、线性轨迹模型（`fable_lin.py`）、旋转常数筛选（`rot_screen_sat.py`）、轨迹验证（`verify_trail.py`、`verify_lin.py`）
- `tools/` — 雪崩汇总、轮常量检查、雪崩并列打破、差分-线性偏差汇总（`dl_report.py`）、旋转差分检查（`rx_check.py`）、ChaCha20-Poly1305 对照基准
- `c/fable_stream_avx2.c` — Fable-Stream 8 路 AVX2 整体实现；`c/dl_bias.c` — 差分-线性偏差测量；`c/bench_stream.c` — 1 GiB 吞吐基准；`Fable-spec-v0.2.md` — 当前规范
- `data/` — 各阶段原始数据（雪崩计数、SAT 结果、筛选 CSV、基准输出）

运行：`python3 test_fable.py`
