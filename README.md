# Fable v0.5（研究草案）

**未经公开密码分析，禁止用于任何真实数据。** All analysis is first-party; Fable must not be used to protect real data until independent cryptanalysis has been published.

Fable 是一个 512 bit ARX 置换（ChaCha 双轮 + 轮常量注入）及其上的 keyed-duplex AEAD（256 bit 密钥、192 bit nonce、256 bit 标签、密钥承诺）、STREAM 分块模式（64 KiB 分块，8 路 AVX2 并行）和海绵哈希。两个参数集：**Fable**（P_12 / P_8，默认）与 **Fable-f**（P_12 / P_6）。

## 文件

- `Fable-spec-v0.5.md` — 当前规范（历史版本 v0.1～v0.4.1 保留）
- `paper/fable.tex`、`paper/refs.bib` — 论文（IACR ToSC `iacrtrans` 格式）
- `fable.py` — Python 参考实现（规范性）；`test_fable.py` — 功能测试与向量生成
- `test_vectors_v0.3.json` — 测试向量（两参数集）；`test_vectors_v0.1.json` — v0.1 向量（= Fable-f）
- `c/` — C 实现：`fable_p.c` 置换、`fable_aead.c` AEAD/XOF、`fable_p_avx2.c` 8 路 AVX2 置换、`fable_stream_avx2.c` Stream 8 路加/解密、`avalanche.c`、`dl_bias.c`、`bench.c`、`bench_stream.c`；`bash c/build.sh` 构建 DLL
- `tests/` — C 版与向量 / Python 参考交叉校验（`check_c_vectors.py`、`check_stream_avx2.py`）
- `sat/` — python-sat 模型：差分（`fable_diff.py`）、线性（`fable_lin.py`）、线性 hull（`lin_hull.py`）、旋转常数筛选（`rot_screen_sat.py`）、轨迹验证（`verify_trail.py`、`verify_lin.py`）
- `tools/` — 雪崩 / 差分-线性 / 旋转差分 / 轮常量检查脚本，ChaCha20-Poly1305 与 AES-GCM 对照基准
- `docs/key-commitment.md`、`docs/security-bounds.md` — 密钥承诺归约、多用户与 STREAM 安全界
- `data/` — 论文与日志中每个数字的原始数据（雪崩计数、SAT 结果与求解日志、筛选 CSV、基准输出）
- `ANALYSIS-LOG.md` — 分析日志：每项结论的复现命令、原始数据路径、判断，以及未做的事
- `reproduce.sh` — 汇总全部复现命令（`--quick` 跳过小时级 SAT 长跑）

## 运行

```
python test_fable.py
bash c/build.sh && python tests/check_c_vectors.py && python tests/check_stream_avx2.py
bash reproduce.sh --quick
```

## 许可

代码、数据与文档以 CC0 1.0 发布（见 `LICENSE`）。
