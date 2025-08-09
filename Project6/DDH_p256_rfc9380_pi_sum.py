# p256_rfc9380_pi_sum.py
# 基于 RFC 9380 的 hash-to-curve（针对 P-256），并集成到 DDH-based Private Intersection-Sum 教学原型
# 说明：纯 Python 实现，供教学/验证使用。生产请用审计过的库或语言实现。
#
# 依赖:
#   pip install phe

import hashlib
import math
from phe import paillier
import random
import sys
from typing import Optional, List, Tuple

# -----------------------------
# P-256 曲线参数（来自 FIPS / RFC 草案）
#  椭圆曲线: y^2 = x^3 + A*x + B (mod p)
#  A = -3
#  B = 0x5ac635... （见下）
#  p = 2^256 - 2^224 + 2^192 + 2^96 - 1
# -----------------------------

# 素域 p
p = 2**256 - 2**224 + 2**192 + 2**96 - 1

# 曲线系数
A = (-3) % p
B = int("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16) % p

# 基点阶 (order n)
n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

# SSWU 参数: RFC 草案中指定 P-256 使用 Z = -2
Z = p - 2  # -2 mod p

# RFC: 对于 P-256，h_eff = 1（cofactor 1），所以 clear_cofactor 为恒等映射
# m = 1（扩域度），W = 2（安全相关）
# 我们采用 SHA-256 作为 XMD 哈希

# 无穷点表示
INF = None

# -----------------------------
# 字节/整数与域运算工具
# -----------------------------
def i2osp(x: int, length: int) -> bytes:
    return x.to_bytes(length, 'big')

def os2ip(b: bytes) -> int:
    return int.from_bytes(b, 'big')

def modinv(a: int, m: int) -> int:
    # 扩展欧几里德求逆
    return pow(a, -1, m)

# -----------------------------
# Tonelli-Shanks: 在有限域上取平方根
# 返回 sqrt(x) 或 None 如果不存在
# -----------------------------
def legendre_symbol(a: int) -> int:
    # 返回 a^{(p-1)/2} mod p，值为 1（是二次剩余）或 p-1（非二次剩余）或 0
    return pow(a % p, (p - 1) // 2, p)

def sqrt_mod_p(a: int) -> Optional[int]:
    """
    Tonelli-Shanks 求解 x^2 = a (mod p)
    若无平方根返回 None
    """
    a = a % p
    if a == 0:
        return 0
    ls = legendre_symbol(a)
    if ls == p - 1:
        # 非二次剩余
        return None
    # 若 p % 4 == 3 的情形，可以直接取
    if p % 4 == 3:
        return pow(a, (p + 1) // 4, p)
    # 否则用 Tonelli-Shanks
    # 将 p-1 写成 q * 2^s, q 奇数
    q = p - 1
    s = 0
    while q % 2 == 0:
        q //= 2
        s += 1
    # 找一个非二次剩余 z
    z = 2
    while legendre_symbol(z) != p - 1:
        z += 1
    # 初始化
    m = s
    c = pow(z, q, p)
    t = pow(a, q, p)
    r = pow(a, (q + 1) // 2, p)
    while True:
        if t % p == 1:
            return r % p
        # 找最小 i (0 < i < m) 使 t^(2^i) = 1
        t2i = t
        found_i = None
        for i2 in range(1, m):
            t2i = pow(t2i, 2, p)
            if t2i == 1:
                found_i = i2
                break
        if found_i is None:
            # 理论上不应到这里
            return None
        i = found_i
        # b = c^(2^(m-i-1))
        b = pow(c, 1 << (m - i - 1), p)
        m = i
        c = pow(b, 2, p)
        t = (t * c) % p
        r = (r * b) % p

# -----------------------------
# EC 点运算（仿射坐标）
# 点表示为 (x, y) 整数对；INF 表示无穷点
# -----------------------------
def is_on_curve(P: Optional[Tuple[int, int]]) -> bool:
    if P is None:
        return True
    x, y = P
    return (y * y - (x * x * x + A * x + B)) % p == 0

def point_neg(P: Optional[Tuple[int, int]]) -> Optional[Tuple[int, int]]:
    if P is None:
        return None
    x, y = P
    return (x, (-y) % p)

def point_add(P: Optional[Tuple[int, int]], Q: Optional[Tuple[int, int]]) -> Optional[Tuple[int, int]]:
    # 点加法：处理无穷与相等情况
    if P is None:
        return Q
    if Q is None:
        return P
    x1, y1 = P
    x2, y2 = Q
    if x1 == x2 and (y1 + y2) % p == 0:
        return None
    if P == Q:
        # 点倍
        return point_double(P)
    # 常规加法
    lam = ((y2 - y1) * modinv((x2 - x1) % p, p)) % p
    xr = (lam * lam - x1 - x2) % p
    yr = (lam * (x1 - xr) - y1) % p
    return (xr, yr)

def point_double(P: Optional[Tuple[int, int]]) -> Optional[Tuple[int, int]]:
    if P is None:
        return None
    x, y = P
    if y == 0:
        return None
    lam = ((3 * x * x + A) * modinv((2 * y) % p, p)) % p
    xr = (lam * lam - 2 * x) % p
    yr = (lam * (x - xr) - y) % p
    return (xr, yr)

def scalar_mul(P: Optional[Tuple[int, int]], e: int) -> Optional[Tuple[int, int]]:
    # 双倍-相加标量乘
    if P is None or e % n == 0:
        return None
    e = e % n
    Q: Optional[Tuple[int, int]] = None
    R = P
    while e > 0:
        if e & 1:
            Q = point_add(Q, R)
        R = point_double(R)
        e >>= 1
    return Q

# -----------------------------
# 字节串扩展: expand_message_xmd (RFC 9380)
#  用 SHA-256
# -----------------------------
def expand_message_xmd(msg: bytes, dst: bytes, len_in_bytes: int) -> bytes:
    """
    RFC 9380 Section 5.4.1: expand_message_xmd using SHA-256
    返回长度为 len_in_bytes 的字节串
    """
    b_in_bytes = hashlib.sha256().digest_size
    # 若 dst 长度大于 255 错误（RFC 规定）
    if len(dst) > 255:
        raise ValueError("dst too long")
    ell = (len_in_bytes + b_in_bytes - 1) // b_in_bytes
    if ell > 255:
        raise ValueError("length too large")
    # DST_prime = DST || I2OSP(len(DST), 1)
    DST_prime = dst + bytes([len(dst)])
    Z_pad = b'\x00' * b_in_bytes
    l_i_b_str = len_in_bytes.to_bytes(2, 'big')
    b0 = hashlib.sha256(Z_pad + msg + l_i_b_str + b'\x00' + DST_prime).digest()
    b_values: List[bytes] = []
    b1 = hashlib.sha256(b0 + b'\x01' + DST_prime).digest()
    b_values.append(b1)
    for i in range(1, ell):
        tmp = bytes(x ^ y for x, y in zip(b0, b_values[i-1]))
        bi = hashlib.sha256(tmp + bytes([i+1]) + DST_prime).digest()
        b_values.append(bi)
    pseudo_random_bytes = b''.join(b_values)[:len_in_bytes]
    return pseudo_random_bytes

# -----------------------------
# hash_to_field: 把消息映射到域元素数组
# 这里我们需要 count = 2（因为 hash_to_curve 要两个 u）
# -----------------------------
def hash_to_field(msg: bytes, count: int, dst: bytes) -> List[int]:
    """
    RFC 9380: hash_to_field with expand_message_xmd SHA256
    返回 count 个 Fp 元素（整数形式）
    """
    # 对于 P-256, m = 1, so L = ceil((log2(p) + 7) / 8)
    L = (p.bit_length() + 7) // 8
    len_in_bytes = count * L
    pseudo_random_bytes = expand_message_xmd(msg, dst, len_in_bytes)
    u: List[int] = []
    for i in range(count):
        elm_offset = i * L
        tv = pseudo_random_bytes[elm_offset:elm_offset + L]
        e_val = os2ip(tv) % p
        u.append(e_val)
    return u

# -----------------------------
# Simplified SWU 映射（RFC 9380 Section 6.6.2）
# 将 field element u 映射到曲线上的点 (x, y)
# 参照 RFC 9380 的伪代码实现（为 Weierstrass 曲线）
# -----------------------------
def map_to_curve_simple_swu(u: int) -> Tuple[int, int]:
    """
    简化 SWU 映射：
    输入 u in Fp，返回曲线点 (x, y)
    参照 RFC 9380: 使用给定的 Z, A, B
    """
    # 1. tv1 = u^2
    tv1 = (u * u) % p
    # 2. tv1 = Z * tv1
    tv1 = (Z * tv1) % p
    # 3. tv2 = tv1^2
    tv2 = (tv1 * tv1) % p
    # 4. x1 = tv1 + tv2
    x1 = (tv1 + tv2) % p
    # 5. x1 = inverse(x1) if x1 != 0 else 0
    if x1 == 0:
        inv_x1 = 0
    else:
        inv_x1 = modinv(x1, p)
    # 6. e1 = inv_x1 == 0
    e1 = (x1 == 0)
    # 7. x1 = (-B / A) * (1 + inv_x1)  if not e1 else  (-B / (Z*A))  (归一化)
    if not e1:
        # -B / A mod p
        minusB_div_A = (-B * modinv(A, p)) % p
        x1 = (minusB_div_A * (1 + inv_x1)) % p
    else:
        # 当 x1==0 时
        minusB_div_ZA = (-B * modinv((Z * A) % p, p)) % p
        x1 = minusB_div_ZA
    # 8. gx1 = x1^3 + A*x1 + B
    gx1 = (x1 * x1 * x1 + A * x1 + B) % p
    # 9. 检查 gx1 是否为平方
    y1 = sqrt_mod_p(gx1)
    if y1 is not None:
        return (x1 % p, y1 % p)
    # 10. 计算 x2 = Z * u^2 * x1
    x2 = (tv1 * x1) % p
    gx2 = (x2 * x2 * x2 + A * x2 + B) % p
    y2 = sqrt_mod_p(gx2)
    if y2 is not None:
        return (x2 % p, y2 % p)
    # 理论上不会走到这里（SSWU 保证其中一个是平方）
    raise ValueError("SSWU failed to find square root (should not happen)")

# -----------------------------
# 统一映射: hash_to_curve (random oracle)
#  对于随机预言机 (RO) 模式:
#    u0, u1 = hash_to_field(msg, 2, DST)
#    Q0 = map_to_curve(u0)
#    Q1 = map_to_curve(u1)
#    R = Q0 + Q1
#    返回清除 cofactor 的 R（P-256 cofactor = 1）
# -----------------------------
def hash_to_curve(msg: bytes, dst: bytes = b"P256-SHA256-SSWU-RO") -> Tuple[int, int]:
    # 1) htf: 生成两个域元素
    u_vals = hash_to_field(msg, 2, dst)
    u0, u1 = u_vals[0], u_vals[1]
    # 2) map_to_curve 每个 u 映射到曲线
    Q0 = map_to_curve_simple_swu(u0)
    Q1 = map_to_curve_simple_swu(u1)
    # 3) 点加并清除 cofactor（P-256 cofactor=1，不做操作）
    R = point_add(Q0, Q1)
    # 检查
    if not is_on_curve(R):
        raise ValueError("resulting point not on curve")
    # 返回点（x, y）
    assert R is not None
    return R

# -----------------------------
# 将点序列化为压缩字节（方便比较/发送）
# 压缩格式：0x02/0x03 + x(32bytes) (标准 X9.62)
# -----------------------------
def point_to_bytes_compressed(P: Optional[Tuple[int, int]]) -> bytes:
    if P is None:
        return b'\x00'
    x, y = P
    prefix = b'\x02' if (y % 2 == 0) else b'\x03'
    return prefix + i2osp(x, 32)

def bytes_compressed_to_point(bts: bytes) -> Optional[Tuple[int, int]]:
    if bts == b'\x00':
        return None
    if len(bts) != 33:
        raise ValueError("invalid compressed length")
    prefix = bts[0]
    x = os2ip(bts[1:])
    # 恢复 y
    rhs = (x * x * x + A * x + B) % p
    y = sqrt_mod_p(rhs)
    if y is None:
        raise ValueError("invalid point (not square)")
    # 选择正确的符号
    if (y % 2 == 0 and prefix == 3) or (y % 2 == 1 and prefix == 2):
        y = (-y) % p
    P = (x, y)
    if not is_on_curve(P):
        raise ValueError("point not on curve")
    return P

# -----------------------------
# 协议模拟：P1 与 P2（在单进程内模拟三轮交互）
#  P1: 拥有 V = {v_i}
#  P2: 拥有 W = {(w_j, t_j)}
#  Paillier 用于同态加密 t_j
#  全部点在曲线层面，用压缩字节发送/比较
# -----------------------------
class Party1:
    def __init__(self, V: List[str]):
        # V: 标识符字符串列表
        self.V = V[:]
        # P1 本地秘密 k1（随机，< n）
        self.k1 = random.randrange(2, n-1)

    def round1_send(self) -> List[bytes]:
        """
        第一步: P1 对每个 v 计算 H(v) = hash_to_curve(v)
                然后计算 scalar * point (k1 * H(v))
                发送压缩字节列表给 P2 （顺序打乱）
        """
        out: List[bytes] = []
        for v in self.V:
            Hv = hash_to_curve(v.encode(), dst=b"P256-SHA256-SSWU-RO")
            # k1 * Hv
            pk = scalar_mul(Hv, self.k1)
            out.append(point_to_bytes_compressed(pk))
        random.shuffle(out)
        return out

    def round3_process(self, Z_bytes_list: List[bytes], pairs: List[Tuple[bytes, 'paillier.EncryptedNumber']], he_pub: 'paillier.PaillierPublicKey') -> Tuple['paillier.EncryptedNumber', int]:
        """
        第三步: P1 收到:
            Z_bytes_list: P2 返回的 H(v)^{k1*k2} 的压缩字节
            pairs: P2 发来的列表，每项为 (H(w_j)^{k2}_bytes, enc_tj)
        P1 对每个 H(w_j)^{k2}_bytes 做 k1 * point -> H(w_j)^{k1*k2}
        然后与 Zset 比较，若匹配则把对应 ciphertext 同态相加
        """
        Zset = set(Z_bytes_list)
        sum_cipher: Optional['paillier.EncryptedNumber'] = None
        match_count = 0
        for (h_wk2_bytes, enc_t) in pairs:
            # 把字节反序列化为点
            P_wk2 = bytes_compressed_to_point(h_wk2_bytes)
            # 用 k1 乘
            combined = scalar_mul(P_wk2, self.k1)
            combined_bytes = point_to_bytes_compressed(combined)
            if combined_bytes in Zset:
                match_count += 1
                if sum_cipher is None:
                    sum_cipher = enc_t
                else:
                    sum_cipher = sum_cipher + enc_t
        if sum_cipher is None:
            # 加密 0 返回（用 P2 的公钥，这里 he_pub 是 P2 的公钥）
            sum_cipher = he_pub.encrypt(0)
        # 返回 (同态和, 交集大小)
        return sum_cipher, match_count

class Party2:
    def __init__(self, W_pairs: List[Tuple[str, int]]):
        """
        W_pairs: 列表 [(w_j, t_j), ...]
        """
        self.W = W_pairs[:]
        # P2 本地秘密 k2
        self.k2 = random.randrange(2, n-1)
        # 生成 Paillier 密钥对（P2 生成）
        self.he_pub, self.he_priv = paillier.generate_paillier_keypair()

    def process_round1(self, p1_bytes_list: List[bytes]) -> List[bytes]:
        """
        P2 接收 P1 发送的 H(v)^{k1}（点压缩字节），对每个做 k2 * point 得到 H(v)^{k1*k2}
        返回 Z（压缩字节列表）
        """
        Z: List[bytes] = []
        for b in p1_bytes_list:
            P = bytes_compressed_to_point(b)
            P_k2 = scalar_mul(P, self.k2)
            Z.append(point_to_bytes_compressed(P_k2))
        random.shuffle(Z)
        return Z

    def round2_send_pairs(self) -> List[Tuple[bytes, 'paillier.EncryptedNumber']]:
        """
        P2 对自己每个 (w_j, t_j):
            H(w_j) = hash_to_curve(w_j)
            compute H(w_j)^{k2} = k2 * H(w_j)
            encrypt t_j 用 Paillier 公钥
        返回 pairs: list of (compressed_bytes_of_H(w)^{k2}, enc_tj)
        """
        pairs: List[Tuple[bytes, 'paillier.EncryptedNumber']] = []
        for (w, t) in self.W:
            Hw = hash_to_curve(w.encode(), dst=b"P256-SHA256-SSWU-RO")
            Hw_k2 = scalar_mul(Hw, self.k2)
            enc_t = self.he_pub.encrypt(t)
            pairs.append((point_to_bytes_compressed(Hw_k2), enc_t))
        random.shuffle(pairs)
        return pairs

    def round3_receive_and_decrypt(self, sum_cipher: 'paillier.EncryptedNumber') -> int:
        """
        P2 用自己的私钥解密 sum_cipher 得到交集和
        """
        s = self.he_priv.decrypt(sum_cipher)
        return s

# -----------------------------
# 简单 Demo
# -----------------------------
def demo():
    V = ["alice@example.com", "bob@example.com", "carol@example.com"]
    W = [("bob@example.com", 10), ("dave@example.com", 5), ("carol@example.com", 7)]

    p1 = Party1(V)
    p2 = Party2(W)

    # Round 1: P1 -> P2
    p1_out = p1.round1_send()

    # Round 2: P2 处理并返回 Z 列表，及 pairs
    Z = p2.process_round1(p1_out)
    pairs = p2.round2_send_pairs()

    # Round 3: P1 处理 Z 和 pairs，计算同态和并发送到 P2
    sum_cipher, match_count = p1.round3_process(Z, pairs, p2.he_pub)

    # P2 解密
    intersection_sum = p2.round3_receive_and_decrypt(sum_cipher)

    print("P1 set V:", V)
    print("P2 set W:", [w for (w, _) in W])
    print("Intersection cardinality (P1 found):", match_count)
    print("Intersection sum (P2 recovers):", intersection_sum)

if __name__ == "__main__":
    # 为了结果可重复，设置随机种子（调试用）
    random.seed(42)
    demo()
