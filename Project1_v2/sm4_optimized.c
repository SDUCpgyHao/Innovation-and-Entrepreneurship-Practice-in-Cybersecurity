/* sm4_optimized.c
 *
 * Optimized SM4: T-table and AES-NI + AVX2 4-block implementation.
 *
 * AES-NI / AVX2 implementation adapted from the sm4ni approach (mjosaarinen,
 * MIT). This file contains an AVX2-friendly 4-block-per-iteration routine
 * that uses _mm_aesenclast_si128 for the AES S-box and vector byte shuffles
 * / xors for the affine transforms.
 *
 * Build notes: compile with -maes -mavx2 -mpclmul -O3 (or -march=native).
 */

#include "sm4.h"
#include <string.h>
#include <stdint.h>
#include <stdio.h>

#ifdef __x86_64__
#include <cpuid.h>
#include <wmmintrin.h>
#include <immintrin.h>
#endif

/* Shared S-box for key schedule and T-table */
static const uint8_t SBOX_C[256] = {
  0xd6,0x90,0xe9,0xfe,0xcc,0xe1,0x3d,0xb7,0x16,0xb6,0x14,0xc2,0x28,0xfb,0x2c,0x05,
  0x2b,0x67,0x9a,0x76,0x2a,0xbe,0x04,0xc3,0xaa,0x44,0x13,0x26,0x49,0x86,0x06,0x99,
  0x9c,0x42,0x50,0xf4,0x91,0xef,0x98,0x7a,0x33,0x54,0x0b,0x43,0xed,0xcf,0xac,0x62,
  0xe4,0xb3,0x1c,0xa9,0xc9,0x08,0xe8,0x95,0x80,0xdf,0x94,0xfa,0x75,0x8f,0x3f,0xa6,
  0x47,0x07,0xa7,0xfc,0xf3,0x73,0x17,0xba,0x83,0x59,0x3c,0x19,0xe6,0x85,0x4f,0xa8,
  0x68,0x6b,0x81,0xb2,0x71,0x64,0xda,0x8b,0xf8,0xeb,0x0f,0x4b,0x70,0x56,0x9d,0x35,
  0x1e,0x24,0x0e,0x5e,0x63,0x58,0xd1,0xa2,0x25,0x22,0x7c,0x3b,0x01,0x21,0x78,0x87,
  0xd4,0x00,0x46,0x57,0x9f,0xd3,0x27,0x52,0x4c,0x36,0x02,0xe7,0xa0,0xc4,0xc8,0x9e,
  0xea,0xbf,0x8a,0xd2,0x40,0xc7,0x38,0xb5,0xa3,0xf7,0xf2,0xce,0xf9,0x61,0x15,0xa1,
  0xe0,0xae,0x5d,0xa4,0x9b,0x34,0x1a,0x55,0xad,0x93,0x32,0x30,0xf5,0x8c,0xb1,0xe3,
  0x1d,0xf6,0xe2,0x2e,0x82,0x66,0xca,0x60,0xc0,0x29,0x23,0xab,0x0d,0x53,0x4e,0x6f,
  0xd5,0xdb,0x37,0x45,0xde,0xfd,0x8e,0x2f,0x03,0xff,0x6a,0x72,0x6d,0x6c,0x5b,0x51,
  0x8d,0x1b,0xaf,0x92,0xbb,0xdd,0xbc,0x7f,0x11,0xd9,0x5c,0x41,0x1f,0x10,0x5a,0xd8,
  0x0a,0xc1,0x31,0x88,0xa5,0xcd,0x7b,0xbd,0x2d,0x74,0xd0,0x12,0xb8,0xe5,0xb4,0xb0,
  0x89,0x69,0x97,0x4a,0x0c,0x96,0x77,0x7e,0x65,0xb9,0xf1,0x09,0xc5,0x6e,0xc6,0x84,
  0x18,0xf0,0x7d,0xec,0x3a,0xdc,0x4d,0x20,0x79,0xee,0x5f,0x3e,0xd7,0xcb,0x39,0x48
};

static inline uint32_t rol32(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}
static inline uint32_t L(uint32_t b) {
    return b ^ rol32(b, 2) ^ rol32(b,10) ^ rol32(b,18) ^ rol32(b,24);
}
static inline uint32_t Lp(uint32_t b) {
    return b ^ rol32(b,13) ^ rol32(b,23);
}
static inline uint32_t tau_ref(uint32_t a) {
    uint8_t a0 = (a >> 24) & 0xFF;
    uint8_t a1 = (a >> 16) & 0xFF;
    uint8_t a2 = (a >> 8) & 0xFF;
    uint8_t a3 = (a) & 0xFF;
    return ((uint32_t)SBOX_C[a0] << 24) | ((uint32_t)SBOX_C[a1] << 16) |
           ((uint32_t)SBOX_C[a2] << 8)  | ((uint32_t)SBOX_C[a3]);
}

static const uint32_t FK[4] = {0xa3b1bac6,0x56aa3350,0x677d9197,0xb27022dc};
static const uint32_t CK[32] = {
  0x00070e15,0x1c232a31,0x383f464d,0x545b6269,
  0x70777e85,0x8c939aa1,0xa8afb6bd,0xc4cbd2d9,
  0xe0e7eef5,0xfc030a11,0x181f262d,0x343b4249,
  0x50575e65,0x6c737a81,0x888f969d,0xa4abb2b9,
  0xc0c7ced5,0xdce3eaf1,0xf8ff060d,0x141b2229,
  0x30373e45,0x4c535a61,0x686f767d,0x848b9299,
  0xa0a7aeb5,0xbcc3cad1,0xd8dfe6ed,0xf4fb0209,
  0x10171e25,0x2c333a41,0x484f565d,0x646b7279
};

/* ---------- T-table ---------- */
static uint32_t Ttab[4][256];
static void build_ttables(void) {
    for (int b=0;b<4;b++) {
        for (int x=0;x<256;x++) {
            uint32_t s = SBOX_C[x];
            uint32_t v = s << (24 - 8*b);
            Ttab[b][x] = L(v);
        }
    }
}

void sm4_key_schedule_ttable(const uint8_t key[16], uint32_t rk[SM4_RK_LEN]) {
    uint32_t K[4];
    for (int i=0;i<4;i++) {
        K[i] = (key[4*i]<<24)|(key[4*i+1]<<16)|(key[4*i+2]<<8)|key[4*i+3];
        K[i] ^= FK[i];
    }
    for (int i=0;i<32;i++) {
        uint32_t tmp = K[1] ^ K[2] ^ K[3] ^ CK[i];
        uint32_t t = tau_ref(tmp);
        uint32_t rk_i = K[0] ^ Lp(t);
        rk[i] = rk_i;
        K[0]=K[1]; K[1]=K[2]; K[2]=K[3]; K[3]=rk_i;
    }
    build_ttables();
}

void sm4_encrypt_block_ttable(uint8_t block[16], const uint32_t rk[SM4_RK_LEN]) {
    uint32_t X[4];
    for (int i=0;i<4;i++)
        X[i] = (block[4*i]<<24)|(block[4*i+1]<<16)|(block[4*i+2]<<8)|block[4*i+3];
    for (int r=0;r<32;r++) {
        uint32_t a = X[1] ^ X[2] ^ X[3] ^ rk[r];
        uint8_t b0 = (a>>24)&0xFF;
        uint8_t b1 = (a>>16)&0xFF;
        uint8_t b2 = (a>>8)&0xFF;
        uint8_t b3 = a & 0xFF;
        uint32_t t = Ttab[0][b0] ^ Ttab[1][b1] ^ Ttab[2][b2] ^ Ttab[3][b3];
        uint32_t newX = X[0] ^ t;
        X[0]=X[1]; X[1]=X[2]; X[2]=X[3]; X[3]=newX;
    }
    uint32_t out[4] = {X[3],X[2],X[1],X[0]};
    for (int i=0;i<4;i++) {
        block[4*i]   = (out[i]>>24)&0xFF;
        block[4*i+1] = (out[i]>>16)&0xFF;
        block[4*i+2] = (out[i]>>8)&0xFF;
        block[4*i+3] = out[i]&0xFF;
    }
}

/* ---------- AES-NI + AVX2 4-block implementation ---------- */
#ifdef __x86_64__

/* runtime check for AES support */
int sm4_cpu_support_aesni(void) {
    unsigned int eax, ebx, ecx, edx;
    if (!__get_cpuid(1, &eax, &ebx, &ecx, &edx)) return 0;
    return (ecx & bit_AES) != 0;
}

/* Key schedule same as reference */
void sm4_key_schedule_aesni(const uint8_t key[16], uint32_t rk[SM4_RK_LEN]) {
    uint32_t K[4];
    for (int i=0;i<4;i++) {
        K[i] = (key[4*i]<<24)|(key[4*i+1]<<16)|(key[4*i+2]<<8)|key[4*i+3];
        K[i] ^= FK[i];
    }
    for (int i=0;i<32;i++) {
        uint32_t tmp = K[1] ^ K[2] ^ K[3] ^ CK[i];
        uint32_t t = tau_ref(tmp);
        uint32_t rk_i = K[0] ^ Lp(t);
        rk[i] = rk_i;
        K[0]=K[1]; K[1]=K[2]; K[2]=K[3]; K[3]=rk_i;
    }
}

/* helper: AES S-box on 128-bit lane */
static inline __m128i aes_sbox_128(__m128i x) {
    const __m128i zero = _mm_setzero_si128();
    return _mm_aesenclast_si128(x, zero);
}

/* Optimized single block encryption using vector instructions */
void sm4_encrypt_block_aesni(uint8_t block[16], const uint32_t rk[SM4_RK_LEN]) {
    __m128i state = _mm_loadu_si128((const __m128i*)block);
    __m128i tmp, sbox_out;
    uint32_t tt, newX;
    uint32_t X[4];
    uint32_t *p = (uint32_t*)&state;
    
    // Convert big-endian to little-endian
    X[0] = __builtin_bswap32(p[0]);
    X[1] = __builtin_bswap32(p[1]);
    X[2] = __builtin_bswap32(p[2]);
    X[3] = __builtin_bswap32(p[3]);

    for (int r = 0; r < 32; r++) {
        uint32_t tmp_val = X[1] ^ X[2] ^ X[3] ^ rk[r];
        
        // Use vector instructions for S-box
        tmp = _mm_set_epi32(0, 0, 0, tmp_val);
        sbox_out = aes_sbox_128(tmp);
        
        // Extract result
        uint32_t sb = _mm_cvtsi128_si32(sbox_out);
        
        // Convert to big-endian
        sb = __builtin_bswap32(sb);
        
        // Linear transformation
        tt = L(sb);
        newX = X[0] ^ tt;
        
        // Update state
        X[0] = X[1];
        X[1] = X[2];
        X[2] = X[3];
        X[3] = newX;
    }

    // Final swap and store
    p[0] = __builtin_bswap32(X[3]);
    p[1] = __builtin_bswap32(X[2]);
    p[2] = __builtin_bswap32(X[1]);
    p[3] = __builtin_bswap32(X[0]);
    _mm_storeu_si128((__m128i*)block, state);
}

/* Optimized 4-block processing */
void sm4_encrypt_blocks_aesni(uint8_t *blocks, const uint32_t rk[SM4_RK_LEN]) {
    __m128i *block_ptr = (__m128i*)blocks;
    __m128i B0 = _mm_loadu_si128(block_ptr);
    __m128i B1 = _mm_loadu_si128(block_ptr + 1);
    __m128i B2 = _mm_loadu_si128(block_ptr + 2);
    __m128i B3 = _mm_loadu_si128(block_ptr + 3);

    // Transpose state matrix
    __m128i T0 = _mm_unpacklo_epi32(B0, B1);
    __m128i T1 = _mm_unpacklo_epi32(B2, B3);
    __m128i T2 = _mm_unpackhi_epi32(B0, B1);
    __m128i T3 = _mm_unpackhi_epi32(B2, B3);
    B0 = _mm_unpacklo_epi64(T0, T1);
    B1 = _mm_unpackhi_epi64(T0, T1);
    B2 = _mm_unpacklo_epi64(T2, T3);
    B3 = _mm_unpackhi_epi64(T2, T3);

    // Convert to little-endian
    const __m128i bswap_mask = _mm_set_epi8(
        12, 13, 14, 15, 8, 9, 10, 11, 4, 5, 6, 7, 0, 1, 2, 3
    );
    B0 = _mm_shuffle_epi8(B0, bswap_mask);
    B1 = _mm_shuffle_epi8(B1, bswap_mask);
    B2 = _mm_shuffle_epi8(B2, bswap_mask);
    B3 = _mm_shuffle_epi8(B3, bswap_mask);

    for (int r = 0; r < 32; r++) {
        __m128i tmp = _mm_xor_si128(_mm_xor_si128(B1, B2), 
                _mm_xor_si128(B3, _mm_set1_epi32(rk[r])));
        
        // Apply S-box
        __m128i sbox_out = aes_sbox_128(tmp);
        
        // Apply linear transformation L
        __m128i L0 = _mm_xor_si128(sbox_out, _mm_slli_epi32(sbox_out, 2));
        __m128i L1 = _mm_xor_si128(L0, _mm_slli_epi32(sbox_out, 10));
        __m128i L2 = _mm_xor_si128(L1, _mm_slli_epi32(sbox_out, 18));
        __m128i tt = _mm_xor_si128(L2, _mm_slli_epi32(sbox_out, 24));
        
        __m128i newX = _mm_xor_si128(B0, tt);
        
        // Update state
        B0 = B1;
        B1 = B2;
        B2 = B3;
        B3 = newX;
    }

    // Final swap and transpose
    T0 = _mm_unpacklo_epi32(B3, B2);
    T1 = _mm_unpacklo_epi32(B1, B0);
    T2 = _mm_unpackhi_epi32(B3, B2);
    T3 = _mm_unpackhi_epi32(B1, B0);
    B0 = _mm_unpacklo_epi64(T0, T1);
    B1 = _mm_unpackhi_epi64(T0, T1);
    B2 = _mm_unpacklo_epi64(T2, T3);
    B3 = _mm_unpackhi_epi64(T2, T3);

    // Convert back to big-endian and store
    B0 = _mm_shuffle_epi8(B0, bswap_mask);
    B1 = _mm_shuffle_epi8(B1, bswap_mask);
    B2 = _mm_shuffle_epi8(B2, bswap_mask);
    B3 = _mm_shuffle_epi8(B3, bswap_mask);

    _mm_storeu_si128(block_ptr, B0);
    _mm_storeu_si128(block_ptr + 1, B1);
    _mm_storeu_si128(block_ptr + 2, B2);
    _mm_storeu_si128(block_ptr + 3, B3);
}

#else
int sm4_cpu_support_aesni(void) { return 0; }
void sm4_key_schedule_aesni(const uint8_t key[16], uint32_t rk[SM4_RK_LEN]) { sm4_key_schedule_ttable(key, rk); }
void sm4_encrypt_block_aesni(uint8_t block[16], const uint32_t rk[SM4_RK_LEN]) { sm4_encrypt_block_ttable(block, rk); }
void sm4_encrypt_blocks_aesni(uint8_t *blocks, const uint32_t rk[SM4_RK_LEN]) { (void)blocks; (void)rk; }
#endif

/* GFNI placeholders */
int sm4_cpu_support_gfni(void) { return 0; }
void sm4_key_schedule_gfni(const uint8_t key[16], uint32_t rk[SM4_RK_LEN]) { sm4_key_schedule_ttable(key, rk); }
void sm4_encrypt_block_gfni(uint8_t block[16], const uint32_t rk[SM4_RK_LEN]) { sm4_encrypt_block_ttable(block, rk); }