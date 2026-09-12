# Fable 分析日志

## 2026-09-13 — 参考实现与初步测试（手机端沙盒）

**实现**：`fable.py`（Fable-P / AEAD / Stream / Hash-XOF），`test_fable.py`，`test_vectors_v0.1.json`。

**功能测试**：AEAD 各长度往返、密文/标签/AD/nonce 篡改检测、Stream 截断与块重排检测 —— 全部通过。

**雪崩测试**（300 组随机状态，全部 512×512 输入-输出比特对）：

| 轮数 | 平均翻转率 | 最大偏差 | 偏差<0.1 比例 |
|---|---|---|---|
| 1 | 0.356 | 0.500 | 44% |
| 2 | 0.500 | 0.153 | 100% |
| 3 | 0.500 | 0.137 | 100% |
| 4 | 0.500 | 0.157 | 100% |

结论：2 轮达到完整雪崩。2～4 轮的最大偏差 ≈0.15 与 300 次采样的统计噪声（4.5σ≈0.13）一致，未见结构性偏差。需在电脑上用 ≥10^5 次采样复测以检测 <0.02 级别的偏差。

**旋转常数粗筛**（150 组随机旋转量，1 轮雪崩均值）：
基线 (16,12,8,7) 排第 42/150，得分 0.357；最高 0.378。
结论：单轮扩散速度不能作为唯一标准，ChaCha 常数是按差分概率而非扩散速度选出的。§7.3 的 2、3 条（差分特征概率界）才是决定性指标，需 SAT/MILP，转电脑完成。**旋转常数维持临时状态。**

## 待办（电脑端）
1. ~~C 实现 + 10^5 级雪崩复测~~（C 实现已完成，见下）
2. CryptoSMT/MILP：Q 函数与 1～6 轮差分特征概率上界，用于旋转常数最终筛选与轮数确认
3. 线性近似、旋转差分（rotational）、slide、固定点分析
4. 密钥承诺归约书面化

---

## 2026-09-13 — 电脑端阶段 1：C 实现 Fable-P / AEAD

**环境**：Windows 11，clang 21.1.0（x86_64-pc-windows-msvc），Python 3.10.9，python-sat 1.9（CaDiCaL 1.5.3），CPU Intel Raptor Lake（24 线程，AVX2）。

**文件**：
- `c/fable_p.h` / `c/fable_p.c` —— 置换。`fable_permute(s, rounds)` 与 `fable.py` 的 `permute` 同语义（r 轮使用 RC[12-r..11]）；另提供 `fable_permute_rot`（自定义旋转量，供筛选）和 `fable_permute_noconst`（轮常量置零，供对称性检查）。
- `c/fable_aead.h` / `c/fable_aead.c` —— AEAD 加/解密与 XOF 的纯 C 移植。
- `c/build.sh` —— 用 clang 构建 `build/fable.dll`。
- `tests/check_c_vectors.py` —— ctypes 加载 DLL，比对测试向量并与 Python 参考交叉校验。

**复现**：
```
bash c/build.sh && python tests/check_c_vectors.py
```

**结果**：`permute12_zero`、5 组 AEAD 向量（加密、解密、篡改检测）、2 组 hash256 向量全部一致；1～12 轮每种轮数各 50 组随机状态、200 组随机旋转量的置换输出与 Python 逐位一致；36 组随机长度组合的 AEAD 密文与 Python 一致。`RESULT: ALL OK`。
