# P-256 RFC9380 Hash-to-Curve + Paillier 同态加密实现的 DDH-based Private Intersection-Sum 协议

**作者**：李云昊  
**邮箱**：1779551322@qq.com  
**许可证**：MIT

---

## 目录

1. [项目简介](#项目简介)  
2. [数学背景与协议推导](#数学背景与协议推导)  
    1. [问题背景](#问题背景)  
    2. [DDH-based Private Intersection-Sum 协议](#ddh-based-private-intersection-sum-协议)  
    3. [数学推导与符号约定](#数学推导与符号约定)  
    4. [RFC9380 Hash-to-Curve](#rfc9380-hash-to-curve)  
    5. [Paillier 同态加密](#paillier-同态加密)  
3. [协议流程与代码映射](#协议流程与代码映射)  
4. [核心代码解析](#核心代码解析)  
    1. [有限域与椭圆曲线运算](#有限域与椭圆曲线运算)  
    2. [Tonelli–Shanks 平方根算法](#tonellishanks-平方根算法)  
    3. [RFC9380 `expand_message_xmd`](#rfc9380-expand_message_xmd)  
    4. [Simplified SWU 映射](#simplified-swu-映射)  
    5. [压缩点编码与解码](#压缩点编码与解码)  
    6. [协议交互类 Party1 与 Party2](#协议交互类-party1-与-party2)  
5. [运行方法](#运行方法)  
6. [测试示例](#测试示例)  
7. [许可证](#许可证)  

---

## 项目简介

本项目实现了论文中 **Figure 2** 所描述的 DDH-based Private Intersection-Sum（基于双线性 Diffie–Hellman 假设的隐私交集求和）协议。  
协议核心思想是：两方在不泄露各自完整数据集的前提下，计算集合交集的元素个数和某个关联数值的总和（如信用分、余额等）。

本实现的主要特点：

1. **曲线选择**：NIST P-256（prime256v1）。
2. **哈希到曲线**：完全实现了 RFC 9380 中的 `hash_to_curve` 流程（RO 模式），包括 `expand_message_xmd`、`hash_to_field`、`map_to_curve_simple_swu` 等。
3. **加密方法**：Paillier 同态加密实现加法上的同态性，用于在加密态下累加交集对应的数值。
4. **协议流程**：严格按照 DDH-based Private Intersection-Sum 三轮交互逻辑实现。

---

## 数学背景与协议推导

### 问题背景

假设两方 P1 和 P2 分别拥有数据集：

- P1：集合 $V = \{ v_1, v_2, \dots, v_m \}$
- P2：集合 $W = \{ (w_1, t_1), (w_2, t_2), \dots, (w_n, t_n) \}$

其中 $t_j$ 是与 $w_j$ 相关的一个数值（例如金额、分数等）。

**目标**：P1 与 P2 协作计算：

1. $|V \cap W|$（交集元素个数）
2. $\sum_{x \in V \cap W} t(x)$（交集元素对应数值的和）

要求在**半诚实模型**下保护隐私：  
- P1 不得获知 $W$ 中不在交集的元素。
- P2 不得获知 $V$ 中不在交集的元素。

---

### DDH-based Private Intersection-Sum 协议

协议基于 Diffie–Hellman（DH）难题的性质：

给定群 $G$、生成元 $g$，若 $a,b$ 为秘密，则 $g^{ab}$ 可由两方分别计算（通过 $g^a$ 与 $g^b$ 交换），而不泄露 $a$ 或 $b$。

在本协议中：

- 群 $G$ 为 P-256 椭圆曲线点集（加法群）。
- 群运算为点加，幂运算对应标量乘。
- 将元素标识符通过 **hash-to-curve** 映射为曲线点 $H(u)$。

---

### 数学推导与符号约定

1. **哈希到曲线**：
   $$
   H: \{0,1\}^* \to E(\mathbb{F}_p)
   $$
   按 RFC9380 将字符串映射到 P-256 曲线上一点。

2. **P1 的处理**：
   - 选随机 $k_1 \in \mathbb{Z}_n^*$
   - 对每个 $v_i \in V$，计算 $P_i = [k_1] H(v_i)$
   - 发送打乱的 $\{ P_i \}$ 给 P2

3. **P2 的处理**：
   - 选随机 $k_2 \in \mathbb{Z}_n^*$
   - 对收到的每个 $P_i$，计算 $Z_i = [k_2] P_i = [k_1 k_2] H(v_i)$
   - 构造 $Z = \{ Z_i \}$ 并打乱，发回给 P1
   - 同时，对每个 $(w_j, t_j) \in W$：
     - 计算 $Q_j = [k_2] H(w_j)$
     - 加密 $t_j$：$C_j = \text{PaillierEnc}(t_j)$
     - 发送 $(Q_j, C_j)$ 给 P1

4. **P1 的交集检测与求和**：
   - 对每个 $(Q_j, C_j)$：
     - 计算 $Q'_j = [k_1] Q_j = [k_1 k_2] H(w_j)$
     - 若 $Q'_j \in Z$，则将 $C_j$ 累加（Paillier 同态加法）
   - 得到密文和 $C_{\text{sum}}$，发送给 P2
   - 记录匹配次数为交集大小

5. **P2 解密**：
   - $\text{PaillierDec}(C_{\text{sum}})$ 得到交集的总和

---

### RFC9380 Hash-to-Curve

RFC 9380 规定了安全将任意字节串映射到椭圆曲线点的方法。本项目实现了 **P256-SHA256-SSWU-RO** 套件：

1. **hash_to_field**：使用 `expand_message_xmd`（SHA-256）生成两个域元素 $u_0, u_1$。
2. **map_to_curve_simple_swu**：将域元素映射到曲线上（Simplified SWU 映射）。
3. **点加**：$Q = \text{SSWU}(u_0) + \text{SSWU}(u_1)$
4. **clear_cofactor**：P-256 的 cofactor = 1，无需额外处理。

数学上保证了：
$$
\forall m \in \{0,1\}^*,\ H(m) \in E(\mathbb{F}_p) \ \text{且近似均匀分布}
$$

---

### Paillier 同态加密

Paillier 公钥加密系统在加法上同态：
$$
E(m_1) \cdot E(m_2) = E(m_1 + m_2)
$$

协议中：
- P2 生成公私钥对 $(pk, sk)$
- P2 用 $pk$ 加密 $t_j$
- P1 对交集中的密文执行乘法（等效于加法）
- P2 用 $sk$ 解密得到求和结果

---

## 协议流程与代码映射

| 协议步骤 | 数学操作 | 代码函数 |
|----------|----------|----------|
| P1: 生成 $[k_1]H(v)$ | `hash_to_curve` + `scalar_mul` | `Party1.round1_send` |
| P2: $[k_2]$ 乘法 | `scalar_mul` | `Party2.process_round1` |
| P2: $[k_2]H(w)$ + Paillier 加密 | `hash_to_curve` + `scalar_mul` + `paillier.encrypt` | `Party2.round2_send_pairs` |
| P1: $[k_1]$ 乘法与比较 | `scalar_mul` + `point_to_bytes_compressed` | `Party1.round3_process` |
| P2: 解密求和 | `paillier.decrypt` | `Party2.round3_receive_and_decrypt` |

---

## 核心代码解析

### 有限域与椭圆曲线运算

文件开头定义了 P-256 曲线的参数 $(p, A, B, n)$，以及基本的域运算 `modinv` 和点运算函数：

- `point_add` / `point_double`：仿射坐标下的椭圆曲线加法与倍加公式。
- `scalar_mul`：使用双倍-相加算法进行标量乘。

公式：
$$
\lambda = \frac{y_2 - y_1}{x_2 - x_1} \quad\Rightarrow\quad x_3 = \lambda^2 - x_1 - x_2
$$

---

### Tonelli–Shanks 平方根算法

函数 `sqrt_mod_p` 用于在有限域 $\mathbb{F}_p$ 中求平方根。  
这是 SSWU 映射中的关键步骤，因为需要从 $x$ 计算 $y = \sqrt{x^3 + Ax + B}$。

- 当 $p \equiv 3 \ (\mathrm{mod}\ 4)$ 可直接用简化公式。
- P-256 不满足该条件，因此实现了完整的 Tonelli–Shanks。

---

### RFC9380 `expand_message_xmd`

函数 `expand_message_xmd` 实现了 RFC 9380 第 5.4.1 节的 XMD 扩展：

1. 输入消息 `msg` 和域分离标签 `dst`。
2. 生成伪随机串长度 `len_in_bytes`。
3. 使用 SHA-256 迭代计算 $b_1, b_2, \dots$。

保证了哈希到域元素的均匀性与可复现性。

---

### Simplified SWU 映射

函数 `map_to_curve_simple_swu` 将域元素 $u$ 映射到曲线点：

- 使用固定参数 $Z = -2$（RFC 推荐值）。
- 通过有理函数变换构造两个候选 $x_1, x_2$。
- 选择使 $g(x) = x^3 + Ax + B$ 为平方数的那个。

该映射保证任意输入 $u$ 都能得到曲线上均匀分布的点。

---

### 压缩点编码与解码

- `point_to_bytes_compressed`：将 $(x, y)$ 转为 33 字节压缩格式（0x02/0x03 + x 坐标）。
- `bytes_compressed_to_point`：从压缩字节恢复 $(x, y)$，使用平方根选择正确符号。

协议中通过压缩点字节比较是否在交集中，避免直接暴露曲线点结构。

---

### 协议交互类 Party1 与 Party2

#### Party1
- `round1_send`：计算 $[k_1]H(v)$，发送压缩点列表。
- `round3_process`：对 P2 的 $(Q_j, C_j)$ 计算 $[k_1]Q_j$ 并与 $Z$ 比较，匹配则累加密文。

#### Party2
- `process_round1`：对 P1 发来的点做 $[k_2]$ 乘法。
- `round2_send_pairs`：对 $w_j$ 计算 $[k_2]H(w_j)$，加密 $t_j$，发送对。
- `round3_receive_and_decrypt`：解密 Paillier 密文和。

---

## 运行方法

1. 安装依赖：
```bash
pip install phe
```
## 运行结果
！[](result.png)