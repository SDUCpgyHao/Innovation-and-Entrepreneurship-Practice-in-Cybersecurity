#ifndef SM4_BASIC_H
#define SM4_BASIC_H

#include <cstdint>

using u32 = uint32_t;
using u8 = uint8_t;

// 密钥扩展：将 128-bit 用户密钥扩展为 32 个轮密钥
void sm4_key_schedule(const u8 key[16], u32 rk[32]);

// 加密单个块：输入 16 字节，输出 16 字节
void sm4_encrypt_block(const u8 input[16], u8 output[16], const u32 rk[32]);

// 解密单个块：输入 16 字节，输出 16 字节
void sm4_decrypt_block(const u8 input[16], u8 output[16], const u32 rk[32]);

#endif
