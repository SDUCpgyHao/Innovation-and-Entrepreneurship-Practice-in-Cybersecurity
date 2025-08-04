#include <immintrin.h>
#include <cstdint>
#include <cstddef>

class SM4_AESNI {
public:
    SM4_AESNI();
    void SetKey(const uint8_t key[16], bool isEncrypt);
    void EncryptBlock(const uint8_t in[16], uint8_t out[16]);
    void DecryptBlock(const uint8_t in[16], uint8_t out[16]);
    void EncryptBlocks(const uint8_t* in, uint8_t* out, size_t blocks); // 多块加密（串行）
private:
    __m128i rk[32]; // 轮密钥
};
