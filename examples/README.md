# Fable 多语言示例实现

每个目录一个自包含文件，实现 **Fable-P**（置换）、**Fable-AEAD**（两个参数集 `fable` = P_12/P_8、`fable-f` = P_12/P_6）和 **Fable-Hash-256**，内嵌 `test_vectors_v0.3.json` 中的向量做自检（P_12/P_8 零态、两参数集的 empty / block / two_blocks 加密 + 解密还原 + 篡改拒绝、hash256("abc") 与 hash256("")），运行后输出 `RESULT: ALL OK`。

**研究草案，未经公开密码分析，禁止用于任何真实数据。** 示例只求正确、可读，不做恒定时间以外的优化；生产级性能实现见仓库 `c/`（标量 + AVX2 ×8）。Fable-Stream（分块模式）未包含在示例中，见 `fable.py` 与 `c/fable_stream_avx2.c`。

| 语言 | 文件 | 运行 | 本机验证 |
|---|---|---|---|
| C (C11) | `c/fable_example.c` | `clang -O2 -std=c11 fable_example.c -o fable_example && ./fable_example` | clang 21 ✔ |
| C++17 | `cpp/fable_example.cpp` | `clang++ -O2 -std=c++17 fable_example.cpp -o fable_example && ./fable_example` | clang++ 21 ✔ |
| Java 11+ | `java/FableExample.java` | `javac FableExample.java && java FableExample` | JDK 21 ✔ |
| Lua 5.3/5.4 | `lua/fable.lua` | `lua fable.lua` | Lua 5.4.6 ✔ |
| Go | `go/fable.go` | `go run fable.go` | Go 1.27 ✔ |
| Rust（无依赖） | `rust/fable.rs` | `rustc -O fable.rs -o fable && ./fable` | rustc 1.98 ✔ |
| JavaScript (Node ≥ 16) | `js/fable.js` | `node fable.js`（也可 `require` 为模块） | Node 24 ✔ |
| C# (.NET 6+) | `csharp/Fable.cs` + `Fable.csproj` | `dotnet run` | .NET 9 ✔ |
| Python 3 | `../fable.py`（规范性参考实现） | `python ../test_fable.py` | 3.10 ✔ |

`bash run_all.sh` 依次构建并运行以上全部示例（需要相应工具链在 PATH 或脚本顶部的路径中）。

## 接口约定（各语言一致）

- `permute(state[16], rounds)`：就地置换，`rounds` 轮使用**最后** `rounds` 个轮常量（P_8 用 RC[4..11]，P_6 用 RC[6..11]）。
- `encrypt(set, key[32], nonce[24], ad, msg)` → `ciphertext || tag[32]`。
- `decrypt(set, key, nonce, ad, ct)` → 明文；认证失败返回空/`null`/`None`/`-1`（按语言习惯），不输出任何明文。标签比较为恒定时间。
- `hash256(data)` → 32 字节。
- 字节序：全部小端；`10*` 填充：消息末块总是存在（空消息也填充一块），AD 为空时不吸收；AD 结束后 `S[15] ^= 0x80000000`。
