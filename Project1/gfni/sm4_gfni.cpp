#include "sm4_gfni.h"
#include <immintrin.h>
#include <cstring>

// 确保编译时启用 AVX-512F 和 GFNI 支持
#ifndef __AVX512F__
#error "AVX-512F support required"
#endif
#ifndef __GFNI__
#error "GFNI support required"
#endif

// 128-bit 循环左移8字节实现（VPROLD128）
static inline __m128i vprold128(__m128i x) {
    // _mm_alignr_epi8(a,b,imm) = shift b:a 右移 imm 字节
    // 左移8字节 = 拼接 x+x 右移 8字节
    return _mm_alignr_epi8(x, x, 8);
}

// 伪密钥扩展函数（实际请按SM4标准实现）
void sm4_key_schedule_gfni(const uint8_t* key, uint32_t* rk) {
    // 简单复制输入key，伪示例
    std::memcpy(rk, key, 16);
    // 实际应该扩展成 32 轮密钥
    for (int i = 4; i < 32; i++) {
        rk[i] = rk[i - 4] ^ i; // 占位符
    }
}

// GFNI 优化的 SM4 加密函数示例
void sm4_encrypt_gfni(const uint8_t* plaintext, uint8_t* ciphertext, const uint32_t* rk) {
    __m128i block = _mm_loadu_si128((const __m128i*)plaintext);

    for (int i = 0; i < 32; i += 4) {
        // 轮函数伪示例
        block = _mm_xor_si128(block, _mm_set1_epi32(rk[i]));
        block = vprold128(block);

        // GFNI 指令，做一个仿射变换示例
        block = _mm_gf2p8affine_epi64_epi8(block, _mm_set1_epi64x(0x1B), 0);
    }

    _mm_storeu_si128((__m128i*)ciphertext, block);
}
