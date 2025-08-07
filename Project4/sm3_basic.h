#ifndef SM3_BASIC_H
#define SM3_BASIC_H

#include <stdint.h>
#include <stddef.h>

void sm3_basic(const uint8_t *message, size_t message_len, uint8_t hash[32]);

#endif // SM3_BASIC_H