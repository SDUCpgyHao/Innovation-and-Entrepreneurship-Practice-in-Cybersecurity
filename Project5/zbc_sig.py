from ecdsa import SigningKey, SECP256k1, VerifyingKey, BadSignatureError

# 生成“中本聪”的密钥对（私钥 + 公钥）
def generate_satoshi_keys():
    sk = SigningKey.generate(curve=SECP256k1)
    vk = sk.get_verifying_key()
    return sk, vk

# 用私钥签名消息
def sign_message(sk, message: bytes):
    return sk.sign(message)

# 验证签名
def verify_signature(vk, message: bytes, signature: bytes):
    try:
        return vk.verify(signature, message)
    except BadSignatureError:
        return False

def main():
    message = b"This is a message from Satoshi."
    
    # 生成真实的中本聪秘钥对
    sk_satoshi, vk_satoshi = generate_satoshi_keys()
    
    # 正常签名
    signature = sign_message(sk_satoshi, message)
    print("签名是否有效:", verify_signature(vk_satoshi, message, signature))  # True
    
    # “伪造”签名：用其他密钥签名，公钥还是中本聪的
    sk_fake, _ = generate_satoshi_keys()  # 另一把私钥
    fake_signature = sign_message(sk_fake, message)
    
    # 验证“伪造”签名（应该是False）
    print("伪造签名是否有效:", verify_signature(vk_satoshi, message, fake_signature))  # False

if __name__ == "__main__":
    main()
