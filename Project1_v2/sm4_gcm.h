/*
 * sm4_gcm.h
 *
 * SM4-GCM API (encrypt/decrypt) using SM4 block cipher.
 *
 * Author: adapted for your project
 */

#ifndef SM4_GCM_H
#define SM4_GCM_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * SM4-GCM encryption
 * 
 * @param key 16-byte SM4 key
 * @param iv IV (nonce) buffer
 * @param iv_len IV length in bytes (typically 12)
 * @param aad Additional Authenticated Data buffer (can be NULL if aad_len=0)
 * @param aad_len AAD length in bytes
 * @param pt Plaintext buffer
 * @param pt_len Plaintext length in bytes
 * @param ct Output ciphertext buffer (same size as plaintext)
 * @param tag Output 16-byte authentication tag
 * @return 0 on success, -1 on error
 */
int sm4_gcm_encrypt(const uint8_t key[16],
                    const uint8_t *iv, size_t iv_len,
                    const uint8_t *aad, size_t aad_len,
                    const uint8_t *pt, size_t pt_len,
                    uint8_t *ct, uint8_t tag[16]);

/**
 * SM4-GCM decryption with tag verification
 * 
 * @param key 16-byte SM4 key
 * @param iv IV (nonce) buffer
 * @param iv_len IV length in bytes (typically 12)
 * @param aad Additional Authenticated Data buffer (can be NULL if aad_len=0)
 * @param aad_len AAD length in bytes
 * @param ct Ciphertext buffer
 * @param ct_len Ciphertext length in bytes
 * @param pt Output plaintext buffer (same size as ciphertext)
 * @param tag 16-byte authentication tag to verify
 * @return 0 on success (tag matches), -1 on error or tag mismatch
 */
int sm4_gcm_decrypt(const uint8_t key[16],
                    const uint8_t *iv, size_t iv_len,
                    const uint8_t *aad, size_t aad_len,
                    const uint8_t *ct, size_t ct_len,
                    uint8_t *pt, const uint8_t tag[16]);

#ifdef __cplusplus
}
#endif

#endif /* SM4_GCM_H */