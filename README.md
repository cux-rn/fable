# Fable v0.3（研究草案）

**未经公开密码分析，禁止用于任何真实数据。**

- `Fable-spec-v0.3.md` — 设计规范
- `fable.py` — Python 参考实现
- `test_fable.py` — 功能测试、测试向量生成、雪崩测试
- `rot_screen.py` — 旋转常数粗筛脚本
- `test_vectors_v0.3.json` — 测试向量（两个参数集）；`test_vectors_v0.1.json` — v0.1 向量（= Fable-f）
- `ANALYSIS-LOG.md` — 分析记录与待办
- `c/` — C 实现（`fable_p.c` 置换、`fable_aead.c` AEAD/XOF、`fable_p_avx2.c` 8 路 AVX2、`fable_stream_avx2.c` Stream 8 路、`avalanche.c`、`dl_bias.c`、`bench*.c`），`bash c/build.sh` 构建 DLL
- `tests/` — C 版与测试向量 / Python 参考交叉校验（`check_c_vectors.py`、`check_stream_avx2.py`）
- `sat/` — python-sat 差分模型（`fable_diff.py`）、线性模型（`fable_lin.py`）、线性 hull 枚举（`lin_hull.py`）、旋转常数筛选、轨迹验证
- `tools/` — 雪崩/差分-线性/旋转差分汇总与检查脚本、ChaCha20-Poly1305 对照基准
- `docs/` — 密钥承诺归约、安全界推导
- `data/` — 各阶段原始数据

运行：`python3 test_fable.py`
