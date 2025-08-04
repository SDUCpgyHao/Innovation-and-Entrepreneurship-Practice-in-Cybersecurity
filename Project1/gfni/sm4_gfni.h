#ifndef SM4_GFNI_H
#define SM4_GFNI_H

#include <cstdint>

#ifdef __cplusplus
extern "C" {
#endif

void sm4_key_schedule_gfni(const uint8_t* key, uint32_t* rk);
void sm4_encrypt_gfni(const uint8_t* plaintext, uint8_t* ciphertext, const uint32_t* rk);

#ifdef __cplusplus
}
#endif

#endif // SM4_GFNI_H
