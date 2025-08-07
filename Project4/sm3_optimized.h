#ifndef SM3_OPTIMIZED_H
#define SM3_OPTIMIZED_H

#include <stdint.h>
#include <stddef.h>

void sm3_optimized_macro(const uint8_t *message, size_t message_len, uint8_t hash[32]);
void sm3_optimized_unroll(const uint8_t *message, size_t message_len, uint8_t hash[32]);
void sm3_optimized_simd(const uint8_t *message, size_t message_len, uint8_t hash[32]);

#endif // SM3_OPTIMIZED_H