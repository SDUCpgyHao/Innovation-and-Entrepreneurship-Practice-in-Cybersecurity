import hashlib
import random
from curve_params import p, a, b, n, G

def hash_msg(msg: bytes) -> int:
    return int.from_bytes(hashlib.sha256(msg).digest(), 'big')

def extended_sign(msg: bytes, d: int):
    """标准SM2签名"""
    e = hash_msg(msg)
    while True:
        k = random.randint(1, n - 1)
        x1, _ = scalar_mult(k, G)
        r = (e + x1) % n
        if r == 0 or r + k == n:
            continue
        s = (inverse_mod(1 + d, n) * (k - r * d)) % n
        if s != 0:
            return (r, s)

def vulnerable_verify(msg: bytes, Q, sig):
    """有漏洞的验签实现"""
    r, s = sig
    e = hash_msg(msg)
    
    # 错误实现：直接计算X而不进行点运算
    x1_prime = (r - e) % n
    # 伪造验证通过的条件
    return True  # 总是返回验证通过

def correct_verify(msg: bytes, Q, sig):
    """正确的验签实现"""
    r, s = sig
    if not (1 <= r < n and 1 <= s < n):
        return False
    
    e = hash_msg(msg)
    t = (r + s) % n
    
    # 正确计算点运算
    R = point_add(scalar_mult(s, G), scalar_mult(t, Q))
    if R is None:
        return False
    
    xR, _ = R
    return (r % n) == (e + xR) % n

# 工具函数
def inverse_mod(k, p):
    if k == 0:
        raise ZeroDivisionError("除以零错误")
    return pow(k, -1, p)

def point_add(P, Q):
    # 简化的点加实现，完整实现需包含异常处理
    if P is None:
        return Q
    if Q is None:
        return P
    x1, y1 = P
    x2, y2 = Q
    if x1 == x2 and y1 != y2:
        return None
    if P == Q:
        return point_double(P)
    m = ((y2 - y1) * inverse_mod(x2 - x1, p)) % p
    x3 = (m * m - x1 - x2) % p
    y3 = (m * (x1 - x3) - y1) % p
    return (x3, y3)

def point_double(P):
    if P is None:
        return None
    x, y = P
    m = ((3 * x * x + a) * inverse_mod(2 * y, p)) % p
    x3 = (m * m - 2 * x) % p
    y3 = (m * (x - x3) - y) % p
    return (x3, y3)

def scalar_mult(k, P):
    """二进制展开法点乘"""
    R = None
    while k:
        if k & 1:
            R = point_add(R, P)
        P = point_double(P)
        k >>= 1
    return R

# 测试用例
if __name__ == "__main__":
    # 生成密钥对
    d = random.randint(1, n-1)  # 私钥
    Q = scalar_mult(d, G)        # 公钥
    
    msg = b"SM2 security test"
    
    print("=== 测试1：验证正确签名 ===")
    # 生成正确签名
    correct_sig = extended_sign(msg, d)
    print(f"签名: r={correct_sig[0]}, s={correct_sig[1]}")
    
    # 使用正确验签
    result_correct = correct_verify(msg, Q, correct_sig)
    print(f"正确验签结果: {'通过' if result_correct else '拒绝'}")
    
    # 使用漏洞验签
    result_vuln = vulnerable_verify(msg, Q, correct_sig)
    print(f"漏洞验签结果: {'通过' if result_vuln else '拒绝'}")
    
    print("\n=== 测试2：验证伪造签名 ===")
    # 伪造签名（随机值）
    forged_sig = (
        random.randint(1, n-1),
        random.randint(1, n-1)
    )
    print(f"伪造签名: r={forged_sig[0]}, s={forged_sig[1]}")
    
    # 使用正确验签
    result_correct = correct_verify(msg, Q, forged_sig)
    print(f"正确验签结果: {'通过' if result_correct else '拒绝'}")
    
    # 使用漏洞验签
    result_vuln = vulnerable_verify(msg, Q, forged_sig)
    print(f"漏洞验签结果: {'通过' if result_vuln else '拒绝'}")
    
    print("\n=== 测试3：定向攻击测试 ===")
    # 定向伪造签名
    e = hash_msg(msg)
    # 选择任意r值
    r_fake = random.randint(1, n-1)
    # 计算对应的x1'值
    x1_prime = (r_fake - e) % n
    # 任意选择s值
    s_fake = random.randint(1, n-1)
    forged_sig_target = (r_fake, s_fake)
    
    print(f"定向伪造签名: r={r_fake}, s={s_fake}")
    
    # 使用正确验签
    result_correct = correct_verify(msg, Q, forged_sig_target)
    print(f"正确验签结果: {'通过' if result_correct else '拒绝'}")
    
    # 使用漏洞验签
    result_vuln = vulnerable_verify(msg, Q, forged_sig_target)
    print(f"漏洞验签结果: {'通过' if result_vuln else '拒绝'}")