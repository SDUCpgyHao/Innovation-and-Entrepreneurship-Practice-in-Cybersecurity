#ifndef SM4_TTABLE_H
#define SM4_TTABLE_H

#include <cstdint>
using u8 = uint8_t;
using u32 = uint32_t;

void sm4_key_schedule(const u8 key[16], u32 rk[32]);
void sm4_encrypt_block_ttable(const u8 in[16], u8 out[16], const u32 rk[32]);

#endif

