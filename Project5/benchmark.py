import time
from sm2_all import extended_sign_scalar, extended_verify_scalar, scalar_mult, G

msg = b"SM2 benchmark test"
d = 0x128B2FA8BD433C6C068C8D803DFF7979  # 示例私钥
Q = scalar_mult(d, G)

methods = ['baseline', 'jacobian', 'naf', 'precmp', 'coz', 'mont', 'flt']
results = {}

def benchmark(method, loops=100):
    start = time.perf_counter()
    success_count = 0
    for _ in range(loops):
        sig = extended_sign_scalar(msg, d, method)
        is_valid = extended_verify_scalar(msg, Q, sig, method)
        if is_valid:
            success_count += 1
        else:
            print(f"⚠️ 验签失败: method={method}, sig={sig}")
    end = time.perf_counter()
    duration = end - start
    success_rate = success_count / loops * 100
    print(f"[{method}] 耗时: {duration:.4f}秒, 成功率: {success_rate:.1f}%")
    return duration

print("⏱ 开始 benchmark...")
for method in methods:
    results[method] = benchmark(method)

print("\n🚀 各方法相对于 baseline 的加速比：")
base = results['baseline']
for method in methods:
    print(f"{method:10s}: {base / results[method]:.2f}x")
