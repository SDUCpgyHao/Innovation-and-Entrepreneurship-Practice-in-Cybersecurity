#include <iostream>
#include <iomanip>
#include <chrono>
#include "sm4_ttable.h"

void print_hex(const char* label, const u8* data, size_t len) {
    std::cout << label;
    for (size_t i = 0; i < len; ++i)
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
    std::cout << std::dec << std::endl;
}

int main() {
    u8 key[16] = {
        0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
        0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10
    };

    u8 plaintext[16] = {
        0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
        0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10
    };

    u8 ciphertext[16];
    u32 rk[32];
    sm4_key_schedule(key, rk);
    print_hex("Ciphertext: ", ciphertext, 16);

    return 0;
}
