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
- `sat/` — python-sat 差分特征模型（`fable_diff.py`）、旋转常数筛选（`rot_screen_sat.py`）、轨迹验证
- `tools/` — 雪崩汇总、轮常量检查、雪崩并列打破
- `data/` — 各阶段原始数据（雪崩计数、SAT 结果、筛选 CSV、基准输出）

运行：`python3 test_fable.py`
