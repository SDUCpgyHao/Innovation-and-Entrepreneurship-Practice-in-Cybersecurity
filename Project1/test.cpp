#include <iostream>
#include <iomanip>
#include "SM4.h"

void print_hex(const u8* data, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
    }
    std::cout << std::dec << std::endl;
}

int main() {
    u8 key[16] = {
        0x01, 0x23, 0x45, 0x67,
        0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98,
        0x76, 0x54, 0x32, 0x10
    };

    u8 plaintext[16] = {
        0x01, 0x23, 0x45, 0x67,
        0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98,
        0x76, 0x54, 0x32, 0x10
    };

    u8 ciphertext[16];
    u8 decrypted[16];
    u32 rk[32];

    sm4_key_schedule(key, rk);

    sm4_encrypt_block(plaintext, ciphertext, rk);
    std::cout << "Ciphertext: ";
    print_hex(ciphertext, 16);

    sm4_decrypt_block(ciphertext, decrypted, rk);
    std::cout << "Decrypted : ";
    print_hex(decrypted, 16);

    // 检查是否加密后能正确解密
    bool match = std::equal(plaintext, plaintext + 16, decrypted);
    std::cout << (match ? "PASS" : "FAIL") << std::endl;

    return 0;
}

