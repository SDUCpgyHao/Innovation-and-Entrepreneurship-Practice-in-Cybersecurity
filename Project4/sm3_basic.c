#include "sm3_basic.h"
#include <string.h>
#include <stdio.h>

// Constants and operations omitted for brevity
// Basic version of SM3 - reference code

#define ROTL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
#define FF0(x, y, z) ((x) ^ (y) ^ (z))
#define GG0(x, y, z) ((x) ^ (y) ^ (z))

// P0 and P1 transformation functions
#define P0(x) ((x) ^ ROTL((x), 9) ^ ROTL((x), 17))
#define P1(x) ((x) ^ ROTL((x), 15) ^ ROTL((x), 23))

static const uint32_t IV[8] = {
    0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
    0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E
};

void sm3_basic(const uint8_t *message, size_t message_len, uint8_t hash[32]) {
    // Padding
    uint64_t bit_len = message_len * 8;
    size_t new_len = ((message_len + 9 + 63) / 64) * 64;
    uint8_t buffer[new_len];
    memset(buffer, 0, new_len);
    memcpy(buffer, message, message_len);
    buffer[message_len] = 0x80;
    for (int i = 0; i < 8; i++) {
        buffer[new_len - 1 - i] = (bit_len >> (8 * i)) & 0xFF;
    }

    // Initialize
    uint32_t V[8];
    memcpy(V, IV, sizeof(IV));

    for (size_t i = 0; i < new_len; i += 64) {
        uint32_t W[68], W1[64];
        for (int j = 0; j < 16; j++) {
            W[j] = (buffer[i + 4*j] << 24) | (buffer[i + 4*j + 1] << 16)
                 | (buffer[i + 4*j + 2] << 8) | buffer[i + 4*j + 3];
        }
        for (int j = 16; j < 68; j++) {
            W[j] = P1(W[j-16] ^ W[j-9] ^ ROTL(W[j-3], 15)) ^ ROTL(W[j-13], 7) ^ W[j-6];
        }
        for (int j = 0; j < 64; j++) {
            W1[j] = W[j] ^ W[j+4];
        }

        uint32_t A = V[0], B = V[1], C = V[2], D = V[3];
        uint32_t E = V[4], F = V[5], G = V[6], H = V[7];

        for (int j = 0; j < 64; j++) {
            uint32_t Tj = (j < 16) ? 0x79cc4519 : 0x7a879d8a;
            Tj = ROTL(Tj, j % 32);
            uint32_t SS1 = ROTL((ROTL(A, 12) + E + Tj), 7);
            uint32_t SS2 = SS1 ^ ROTL(A, 12);
            uint32_t TT1 = FF0(A, B, C) + D + SS2 + W1[j];
            uint32_t TT2 = GG0(E, F, G) + H + SS1 + W[j];
            D = C;
            C = ROTL(B, 9);
            B = A;
            A = TT1;
            H = G;
            G = ROTL(F, 19);
            F = E;
            E = P0(TT2);
        }

        V[0] ^= A; V[1] ^= B; V[2] ^= C; V[3] ^= D;
        V[4] ^= E; V[5] ^= F; V[6] ^= G; V[7] ^= H;
    }

    for (int i = 0; i < 8; i++) {
        hash[4*i + 0] = (V[i] >> 24) & 0xFF;
        hash[4*i + 1] = (V[i] >> 16) & 0xFF;
        hash[4*i + 2] = (V[i] >> 8) & 0xFF;
        hash[4*i + 3] = V[i] & 0xFF;
    }
}