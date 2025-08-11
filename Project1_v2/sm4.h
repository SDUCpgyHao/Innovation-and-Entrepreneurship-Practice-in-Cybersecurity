/* sm4.h
 *
 * Public API for SM4 implementations (basic, ttable, aesni/avx2)
 *
 * Note: AES-NI/AVX2 implementation adapted from ideas in mjosaarinen/sm4ni (MIT).
 */

#ifndef SM4_H
#define SM4_H

#include <stdint.h>
#include <stddef.h>

#define SM4_RK_LEN 32

/* Basic implementation */
void sm4_key_schedule_basic(const uint8_t key[16], uint32_t rk[SM4_RK_LEN]);
void sm4_encrypt_block_basic(uint8_t block[16], const uint32_t rk[SM4_RK_LEN]);

/* T-table implementation */
void sm4_key_schedule_ttable(const uint8_t key[16], uint32_t rk[SM4_RK_LEN]);
void sm4_encrypt_block_ttable(uint8_t block[16], const uint32_t rk[SM4_RK_LEN]);

/* AES-NI + AVX2 4-block vectorized implementation */
int sm4_cpu_support_aesni(void);
void sm4_key_schedule_aesni(const uint8_t key[16], uint32_t rk[SM4_RK_LEN]);
void sm4_encrypt_block_aesni(uint8_t block[16], const uint32_t rk[SM4_RK_LEN]);
/* process 4 blocks in-place (helper for bench if desired) */
void sm4_encrypt_blocks_aesni(uint8_t *blocks /*4*16 bytes*/, const uint32_t rk[SM4_RK_LEN]);

/* GFNI placeholder */
int sm4_cpu_support_gfni(void);
void sm4_key_schedule_gfni(const uint8_t key[16], uint32_t rk[SM4_RK_LEN]);
void sm4_encrypt_block_gfni(uint8_t block[16], const uint32_t rk[SM4_RK_LEN]);

#endif /* SM4_H */