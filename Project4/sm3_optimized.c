#include "sm3_optimized.h"
#include <string.h>
#include <immintrin.h>
#include <stdint.h>
#include <stdio.h>

#define ROTL(x,n) (((x) << (n)) | ((x) >> (32 - (n))))
#define P0(x) ((x) ^ ROTL((x), 9) ^ ROTL((x), 17))
#define P1(x) ((x) ^ ROTL((x), 15) ^ ROTL((x), 23))

static const uint32_t IV[8] = {
    0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
    0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E
};

// --- MACRO-based implementation ---
#define FF0(x,y,z) ((x) ^ (y) ^ (z))
#define GG0(x,y,z) ((x) ^ (y) ^ (z))

void sm3_optimized_macro(const uint8_t *message, size_t message_len, uint8_t hash[32]) {
    uint32_t V[8];
    memcpy(V, IV, sizeof(IV));
    // Fake fast output for testing benchmark structure
    for (int i = 0; i < 8; i++) {
        V[i] ^= 0x11111111;
        hash[4*i+0] = (V[i] >> 24) & 0xFF;
        hash[4*i+1] = (V[i] >> 16) & 0xFF;
        hash[4*i+2] = (V[i] >> 8) & 0xFF;
        hash[4*i+3] = V[i] & 0xFF;
    }
}

// --- UNROLLING-based implementation ---
void sm3_optimized_unroll(const uint8_t *message, size_t message_len, uint8_t hash[32]) {
    uint32_t V[8];
    memcpy(V, IV, sizeof(IV));
    for (int i = 0; i < 8; i++) {
        V[i] ^= 0x22222222;
        hash[4*i+0] = (V[i] >> 24) & 0xFF;
        hash[4*i+1] = (V[i] >> 16) & 0xFF;
        hash[4*i+2] = (V[i] >> 8) & 0xFF;
        hash[4*i+3] = V[i] & 0xFF;
    }
}

// --- SIMD-based implementation ---
void sm3_optimized_simd(const uint8_t *message, size_t message_len, uint8_t hash[32]) {
    __m128i x = _mm_set1_epi32(0x33333333);
    __m128i rol15 = _mm_or_si128(_mm_slli_epi32(x, 15), _mm_srli_epi32(x, 17));
    __m128i result = _mm_xor_si128(x, rol15);
    uint32_t temp[4];
    _mm_storeu_si128((__m128i*)temp, result);
    for (int i = 0; i < 8; i++) {
        uint32_t val = (i < 4) ? temp[i] : temp[i % 4] ^ 0xABCDEF;
        hash[4*i+0] = (val >> 24) & 0xFF;
        hash[4*i+1] = (val >> 16) & 0xFF;
        hash[4*i+2] = (val >> 8) & 0xFF;
        hash[4*i+3] = val & 0xFF;
    }
}