#include "sm4_AESNI.h"
#include <iostream>
#include <cstring>

int main() {
    uint8_t key[16] = {
        0x01, 0x23, 0x45, 0x67,
        0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98,
        0x76, 0x54, 0x32, 0x10
    };

    uint8_t plain[16] = {
        0x01, 0x23, 0x45, 0x67,
        0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98,
        0x76, 0x54, 0x32, 0x10
    };

    uint8_t cipher[16] = {};
    uint8_t decrypted[16] = {};

    SM4_AESNI sm4;
    sm4.SetKey(key, true);
    sm4.EncryptBlock(plain, cipher);

    sm4.SetKey(key, false);
    sm4.DecryptBlock(cipher, decrypted);

    std::cout << "Plaintext : ";
    for (int i = 0; i < 16; ++i) printf("%02X ", plain[i]);
    std::cout << "\nCiphertext: ";
    for (int i = 0; i < 16; ++i) printf("%02X ", cipher[i]);
    std::cout << "\nDecrypted : ";
    for (int i = 0; i < 16; ++i) printf("%02X ", decrypted[i]);
    std::cout << "\n";

    if (std::memcmp(plain, decrypted, 16) == 0) {
        std::cout << "[PASS] AESNI SM4 encryption/decryption test\n";
    } else {
        std::cout << "[FAIL] Decryption result mismatch\n";
    }

    return 0;
}

