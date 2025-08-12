# Project3 — Poseidon2 (t=3, d=5) circom + snarkjs PoC (BN254)

## 摘要（Abstract）
本项目实现并演示了 Poseidon2 哈希函数的电路化实现（参数：t=3, d=5），基于 BN254 素域（alt_bn128），并配套：
- 一个可用于 circom 的电路 `circuits/Poseidon2_t3_bn254.circom`（包含真实的 round constants）
- 用于生成测试输入的参考实现脚本 `scripts/generate_input.js`（纯 JS/BigInt，直接计算 pubHash）
- 自动化运行脚本 `scripts/run_pipeline.sh`（编译 → 计算 witness → Groth16 setup → 证明 → 验证）
- 详细报告性质的 README（本文件）说明数学推导、参数来源、实现细节与测试方法。

> **警告**：本仓库把从开源实现（jf_poseidon2）提取的 BN254 常量嵌入了电路，但线性层使用的是常见的小整数 MAT_EXT / MAT_INT 。
---
## 目录结构
```
project3-poseidon2_t3_bn254/
├─ circuits/
│  ├─ Poseidon2_t3_bn254.circom
│  └─ constants/poseidon2_t3_bn254_constants.json
├─ inputs/
│  └─ input.json   (生成脚本会写入)
├─ scripts/
│  ├─ generate_input.js
│  └─ run_pipeline.sh
├─ build/           (circom 构建输出)
├─ README.md
```

---
## 一、背景与目标
Poseidon2 是一类为零知识证明系统（如 SNARK）设计的哈希函数，它优化了哈希为电路中的约束数：使用低开销（乘法、加法与稀疏矩阵乘）与少量的非线性 S-box（通常 x^5）。本项目目标：
1. 在 circom 中实现 Poseidon2 单-block sponge（rate=2, capacity=1）电路，参数为 t=3, d=5。
2. 使用来自权威实现（jf_poseidon2）为 BN254 素域生成的 round constants，保证参数学上的正确性。
3. 提供参考 JS 实现以在同一域上计算 reference hash（pubHash），并提供自动化脚本以运行 snarkjs Groth16 流程，验证电路正确性与证明生成。

---
## 二、Poseidon2 算法简介（数学表示）

### 2.1 状态与吸收（State and Absorb）
Poseidon2 使用长度为 `t` 的状态向量 `S = (s_0, s_1, ..., s_{t-1})`。在单块 sponge 模式下，输入 `X` 被分为 `rate` 个 field 元素并吸收到 `s_0..s_{rate-1}`：
```
for i in 0..rate-1: s_i <- s_i + X_i  (mod p)
```

本项目取 `t = 3`，`rate = 2`，因此吸收两个 field 元素到 `s_0,s_1`，`s_2` 充当 capacity 元素。状态初始为零。

### 2.2 S-box 与线性层（S-box and Linear Layer）
Poseidon2 的非线性层采用 S-box: `φ(x) = x^d`，本实例中 `d=5`。

每一轮（round）由：添加轮常数（round constants）→ 应用 S-box（全轮对所有元素，部分轮只对 s_0）→ 线性层（MDS 或稀疏化矩阵）组成。

记第 r 轮前状态为 `S^(r)`，相应的常数 `RC_r = (rc_{r,0},...,rc_{r,t-1})`（外轮）或单个 `rc_r`（内轮，作用于 s_0）。则：
- 全轮（full round）:
  1. `a_i = s_i + rc_{r,i}`
  2. `b_i = φ(a_i)` for all i
  3. `s' = M_ext * b`

- 部分轮（partial round）:
  1. `a_0 = s_0 + rc_r` ; `a_i = s_i` for i>0
  2. `b_0 = φ(a_0)` ; `b_i = a_i` for i>0
  3. `s' = M_int * b`

这里 `M_ext` 与 `M_int` 分别为全轮与部分轮所用的线性映射矩阵。
在很多实现中，M_int 被表示成 `Pre * Sparse` 的分解以减少乘法开销——在电路中可以直接使用分解后的形式以降低约束。

### 2.3 轮次与安全参数
Poseidon2 通过选择合适数量的 full / partial rounds 来满足强度（比如 128-bit）。我们使用了 jf_poseidon2 给出的 BN254 参数（fullRounds=8，partialRounds=56），并使用对应的 round constants（RC3_EXT, RC3_INT）。

---
## 三、参数来源与一致性说明
- RC3_EXT, RC3_INT 来自开源实现 `jf_poseidon2`（BN254 instantiation）。这些是在 BN254 域（ark_bn254::Fr）上生成的常量，保证与实施库的 reference vectors 一致。
- 为了代码清晰与电路可读性，电路示例中使用了简明的 MAT_EXT / MAT_INT 矩阵（小整数）。若需要 1:1 等价于 `jf_poseidon2` 的稀疏线性层实现（Pre + Sparse），应将线性层按照该实现的分解直接在电路中写出（这将降低电路中的乘法数并和参考向量完全一致）。

---
## 四、电路实现关键点与设计决策
1. **S-box 实现**：电路直接通过 `x*x*x*x*x` 实现 `x^5`，不使用 exponentiation via pow helper，因为 `x^5` 在约束上可被直接展开且语义清晰。
2. **常数表示**：所有 round constants 以十进制 BigInt 写入 circom 文件，circom 在编译时会把这些处理成对应 field 元素（编译与 witness 时，输入须在相同素域内）。
3. **线性层选择**：采用 MAT_EXT / MAT_INT 的明确矩阵乘法形式，便于验证正确性、便于调试。但若目标是最小化电路约束，应使用稀疏分解（Pre+Sparse）以减少乘法数量。
4. **输入长度**：此电路只处理单个 block 的哈希（rate=2）。若需要哈希任意长度消息，应实现 sponge 多块吸收/压缩逻辑和必要的 padding（本项目为课程作业/PoC，聚焦单块）。
5. **验证一致性**：`scripts/generate_input.js` 提供纯 JS reference 实现，使用相同的常数执行 permutation 并计算 `pubHash`。在运行 circom + snarkjs 前，先用该脚本生成 inputs/input.json 保证 `pubHash` 为正确的参考输出。

---
## 五：如何跑通（使用说明）
1. 安装依赖：
   - Node.js（>=14）
   - circom v2（按官方文档安装）
   - snarkjs (`npm install -g snarkjs`)

2. 生成测试输入（例如 preimage = [123,456]）:
```bash
node scripts/generate_input.js 123 456
# 会生成 inputs/input.json，其中 pubHash 为 reference 输出
```

3. 编译电路并运行 snarkjs pipeline（示例）:
```bash
bash scripts/run_pipeline.sh
```

4. 产物位于 `build/`，包括 `witness.wtns`, `proof.json`, `public.json`, zkey 与 ptau 文件等。

---
## 六：验证结果与测试建议
- 使用 `scripts/generate_input.js` 计算的 `pubHash` 与电路计算出的 `state[0]` 必须一致；你可以在计算 witness 或引入调试信号打印中验证中间状态（使用 `.sym` 符号文件辅助调试）。
- 若需要与 `jf_poseidon2` 的 fixed_test_vector 逐轮一一对应，请告知，我会把电路线性层改写为该实现的 Pre+Sparse 形式以保证每一轮输出完全一致（现在的 MAT_INT/MAT_EXT 保持算法一致性，但未必逐轮输出字面一致）。

---
## 七：后续改进（建议）
1. 将线性层替换成 `Pre + Sparse` 分解以优化约束与乘法成本。
2. 支持消息分片（多 block）与 padding 规则实现全 sponge 接口。
3. 将证明流水线自动化（CI）并在 zkey 生成时执行多方 ceremony。
4. 对电路做约束计数/性能分析并在需要时重写成更优的门级实现（例如采用 ROM 或位操作辅助）。

---
## 八：参考与致谢
- Poseidon2 论文与参数生成方法（ePrint 2023/323）
- jf_poseidon2 开源实现（常量来源）
- circom 文档与 snarkjs 工具链

---
## 使用许可
该仓库以教学/学习为目的，随意复用、修改或扩展。
