```text
poc.py 的算法推导
1. SM2 签名生成（extended_sign 函数）
输入：消息 msg，私钥 d
输出：签名 (r, s)
步骤推导：
1.	计算消息哈希：
e=Hash(msg)mod  ne=Hash(msg)modn
（代码中通过 hash_msg(msg) 实现，使用 SHA-256）
2.	生成临时随机数 k：
k∈[1,n−1]k∈[1,n−1]
（代码中为 random.randint(1, n-1)）
3.	计算曲线点 (x1,y1)=k×G(x1,y1)=k×G：
（代码中通过 scalar_mult(k, G) 实现标量乘法）
4.	计算 r：
r=(e+x1)mod  nr=(e+x1)modn
o	如果 r=0r=0 或 r+k=nr+k=n，需重新选择 k（避免安全性问题）。
5.	计算 s：
s=(1+d)−1⋅(k−r⋅d)mod  ns=(1+d)−1⋅(k−r⋅d)modn
o	(1 + d)^{-1} 是模逆运算（代码中通过 inverse_mod(1 + d, n) 实现）。
o	如果 s=0s=0，需重新选择 k。
最终签名：(r, s)
 
2. 正确的验签（correct_verify 函数）
输入：消息 msg，公钥 Q，签名 (r, s)
输出：True（验签通过）或 False（验签失败）
步骤推导：
1.	检查 r,sr,s 范围：
1≤r<n1≤r<n，1≤s<n1≤s<n。
2.	计算消息哈希：
e=Hash(msg)mod  ne=Hash(msg)modn。
3.	计算中间值 tt：
t=(r+s)mod  nt=(r+s)modn。
4.	计算曲线点：
R=s×G+t×QR=s×G+t×Q
（代码中通过 point_add(scalar_mult(s, G), scalar_mult(t, Q)) 实现）。
5.	验证 RR 的 x 坐标：
o	如果 RR 是无穷远点（无效点），验签失败。
o	否则，提取 RR 的 x 坐标 xRxR，并检查：
(e+xR)mod  n≡rmod  n(e+xR)modn≡rmodn。
 
3. 有漏洞的验签（vulnerable_verify 函数）
漏洞原理：
该函数未实际计算椭圆曲线点运算，而是直接假设签名有效，返回 True。攻击者可利用此漏洞伪造任意签名通过验证。
错误实现：
```
```python
def vulnerable_verify(msg: bytes, Q, sig):
    r, s = sig
    e = hash_msg(msg)
    x1_prime = (r - e) % n  # 错误：未验证椭圆曲线点
    return True  # 总是返回验证通过
```
```text
攻击者如何伪造签名？
1.	选择任意 r∈[1,n−1]r∈[1,n−1]。
2.	计算 x1′=(r−e)mod  nx1′=(r−e)modn（但未验证 x1′x1′ 是否对应有效曲线点）。
3.	选择任意 s∈[1,n−1]s∈[1,n−1]。
4.	提交伪造的签名 (r, s)，漏洞验签会直接通过。
 
4. 代码中的测试案例
poc.py 包含 3 类测试：
1.	测试 1：验证正确签名
	用 extended_sign 生成合法签名，验证 correct_verify 和 vulnerable_verify的结果。
2.	测试 2：验证随机伪造签名
	随机生成 (r, s)，测试是否被正确拒绝。
3.	测试 3：定向攻击漏洞验签
	构造 r=e+x1′mod  nr=e+x1′modn，其中 x1′x1′ 是任意值（无需对应真实曲线点）。
	漏洞验签会通过，而正确验签会拒绝。
 
关键数学问题
1.	为什么 r+k=nr+k=n 时需要重试？
	避免签名方程 s=(1+d)−1(k−rd)s=(1+d)−1(k−rd) 中出现 k=n−rk=n−r，可能导致密钥泄露。
2.	为什么验签需要计算 s×G+t×Qs×G+t×Q？
	通过公钥 Q=d×GQ=d×G 和签名方程可推导：
s×G+t×Q=(k−rd)×G+(r+s)×d×G=k×Gs×G+t×Q=(k−rd)×G+(r+s)×d×G=k×G
	因此，验签恢复出 k×Gk×G 的 x 坐标应与 r−er−e 匹配。
 
总结
•	poc.py 演示了 SM2 的正确签名/验签流程，并故意实现了一个不安全的验签函数，用于对比安全性。
•	漏洞本质：跳过椭圆曲线点运算的验签，会导致签名可被任意伪造。
•	实际应用：必须严格实现验签的所有步骤，尤其是标量乘法和点加法。
```
