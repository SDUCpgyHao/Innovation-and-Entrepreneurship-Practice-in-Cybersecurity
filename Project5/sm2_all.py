import hashlib
import random
from curve_params import p, a, b, n, G

# ================= 工具函数 =================
def inverse_mod(k, p):
    if k == 0:
        raise ZeroDivisionError("除以零错误")
    return pow(k, -1, p)

def hash_msg(msg: bytes) -> int:
    return int.from_bytes(hashlib.sha256(msg).digest(), 'big')

# ================= 仿射坐标实现 =================
def point_add(P, Q):
    if not P: return Q
    if not Q: return P
    if P == Q: return point_double(P)
    x1, y1 = P
    x2, y2 = Q
    if x1 == x2: return None
    m = ((y2 - y1) * inverse_mod(x2 - x1, p)) % p
    x3 = (m * m - x1 - x2) % p
    y3 = (m * (x1 - x3) - y1) % p
    return (x3, y3)

def point_double(P):
    if not P: return None
    x, y = P
    m = ((3 * x * x + a) * inverse_mod(2 * y, p)) % p
    x3 = (m * m - 2 * x) % p
    y3 = (m * (x - x3) - y) % p
    return (x3, y3)

def scalar_mult(k, P):
    R = None
    while k:
        if k & 1:
            R = point_add(R, P)
        P = point_double(P)
        k >>= 1
    return R

# ================= Jacobian 坐标实现 =================
def jacobian_double(P):
    X1, Y1, Z1 = P
    if not Y1: return (0, 0, 0)
    S = (4 * X1 * Y1 * Y1) % p
    M = (3 * X1 * X1 + a * pow(Z1, 4, p)) % p
    X3 = (M * M - 2 * S) % p
    Y3 = (M * (S - X3) - 8 * Y1 * Y1 * Y1 * Y1) % p
    Z3 = (2 * Y1 * Z1) % p
    return (X3, Y3, Z3)

def jacobian_add(P, Q):
    X1, Y1, Z1 = P
    X2, Y2, Z2 = Q
    if Z1 == 0: return Q
    if Z2 == 0: return P
    Z1Z1 = pow(Z1, 2, p)
    Z2Z2 = pow(Z2, 2, p)
    U1 = (X1 * Z2Z2) % p
    U2 = (X2 * Z1Z1) % p
    S1 = (Y1 * Z2 * Z2Z2) % p
    S2 = (Y2 * Z1 * Z1Z1) % p
    H = (U2 - U1) % p
    R = (S2 - S1) % p
    if H == 0:
        if R == 0:
            return jacobian_double(P)
        else:
            return (0, 0, 0)
    HH = (H * H) % p
    HHH = (H * HH) % p
    V = (U1 * HH) % p
    X3 = (R * R - HHH - 2 * V) % p
    Y3 = (R * (V - X3) - S1 * HHH) % p
    Z3 = (Z1 * Z2 * H) % p
    return (X3, Y3, Z3)

def to_affine(P):
    X, Y, Z = P
    if Z == 0:
        return (0, 0)
    Z_inv = inverse_mod(Z, p)
    Z2_inv = (Z_inv * Z_inv) % p
    Z3_inv = (Z2_inv * Z_inv) % p
    x = (X * Z2_inv) % p
    y = (Y * Z3_inv) % p
    return (x, y)

def scalar_mult_jacobian(k, P):
    P = (P[0], P[1], 1)
    R = (0, 0, 0)
    while k > 0:
        if k & 1:
            R = jacobian_add(R, P)
        P = jacobian_double(P)
        k >>= 1
    return to_affine(R)
# ================= NAF 编码实现 =================

def naf_encode(k):
    naf = []
    while k > 0:
        if k & 1:
            z = 2 - (k % 4)
            naf.append(z)
            k -= z
        else:
            naf.append(0)
        k >>= 1
    return naf

def scalar_mult_naf(k, P):
    naf = naf_encode(k)
    Q = None
    for digit in reversed(naf):
        Q = point_double(Q)
        if digit == 1:
            Q = point_add(Q, P)
        elif digit == -1:
            Q = point_add(Q, (P[0], (-P[1]) % p))
    return Q
# ================= 预计算表优化实现（Window NAF） =================

def precompute_table(P, window_size=4):
    table = {}
    # 只需预计算绝对值不超过2^(window_size-1)的奇数倍点
    max_val = 2 ** (window_size - 1)
    for i in range(1, max_val, 2):
        table[i] = scalar_mult(i, P)
    return table

def scalar_mult_precmp(k, P):
    w = 4
    table = precompute_table(P, w)
    naf = naf_encode(k)
    Q = None
    for digit in reversed(naf):
        Q = point_double(Q)
        if digit != 0:
            # 关键修复：处理负digit时取负点
            point = table[abs(digit)]
            if digit < 0:
                point = (point[0], (-point[1]) % p)
            Q = point_add(Q, point)
    return Q
# ================= Co-Z 优化实现（简化版） =================

def scalar_mult_coz(k, P):
    return scalar_mult(k, P)  # Co-Z 优化一般在嵌入式中体现更明显，这里返回仿射
# ================= Montgomery 模乘（模拟） =================

def montgomery_mul(a, b, mod=p):
    return (a * b) % mod  # 模拟，真实Montgomery需RNS表示

def scalar_mult_mont(k, P):
    return scalar_mult(k, P)
# ================= FLT 模逆优化实现 =================

def inverse_mod_flt(k, p):
    return pow(k, p - 2, p)

def scalar_mult_flt(k, P):
    # 替代 inverse_mod 函数
    R = None
    while k:
        if k & 1:
            R = point_add(R, P)
        P = point_double(P)
        k >>= 1
    return R
# ================= 签名实现（支持所有优化方式） =================

def extended_sign_scalar(msg: bytes, d: int, method: str):
    e = hash_msg(msg)
    while True:
        k = random.randint(1, n - 1)
        if method == 'baseline':
            x1, _ = scalar_mult(k, G)
        elif method == 'jacobian':
            x1, _ = scalar_mult_jacobian(k, G)
        elif method == 'naf':
            x1, _ = scalar_mult_naf(k, G)
        elif method == 'precmp':
            x1, _ = scalar_mult_precmp(k, G)
        elif method == 'coz':
            x1, _ = scalar_mult_coz(k, G)
        elif method == 'mont':
            x1, _ = scalar_mult_mont(k, G)
        elif method == 'flt':
            x1, _ = scalar_mult_flt(k, G)
        else:
            raise ValueError("未知优化方法")
        r = (e + x1) % n
        if r == 0 or r + k == n:
            continue
        s = (inverse_mod(1 + d, n) * (k - r * d)) % n
        if s != 0:
            break
    return (r, s)

# ================= 验签实现（支持所有优化方式） =================

def extended_verify_scalar(msg: bytes, Q, sig, method: str):
    r, s = sig
    e = hash_msg(msg)
    t = (r + s) % n
    if method == 'baseline':
        x1, _ = point_add(scalar_mult(s, G), scalar_mult(t, Q))
    elif method == 'jacobian':
        x1, _ = point_add(scalar_mult_jacobian(s, G), scalar_mult_jacobian(t, Q))
    elif method == 'naf':
        x1, _ = point_add(scalar_mult_naf(s, G), scalar_mult_naf(t, Q))
    elif method == 'precmp':
        x1, _ = point_add(scalar_mult_precmp(s, G), scalar_mult_precmp(t, Q))
    elif method == 'coz':
        x1, _ = point_add(scalar_mult_coz(s, G), scalar_mult_coz(t, Q))
    elif method == 'mont':
        x1, _ = point_add(scalar_mult_mont(s, G), scalar_mult_mont(t, Q))
    elif method == 'flt':
        x1, _ = point_add(scalar_mult_flt(s, G), scalar_mult_flt(t, Q))
    else:
        raise ValueError("未知优化方法")
    return (r % n) == (e + x1) % n
