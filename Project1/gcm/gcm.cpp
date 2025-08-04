#include <cstdint>
#include <cstring>
#include <iostream>
#include <iomanip>
#include <string>
#include <vector>
#include <random>
#include <chrono>  

using namespace std;

// --- 保留原始Sbox和常量 ---
static const uint8_t Sbox[256] = { 
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
static const uint8_t MK[16] = { 0x01,0x23,0x45,0x67, 0x89,0xab,0xcd,0xef,
                                0xfe,0xdc,0xba,0x98, 0x76,0x54,0x32,0x10 };
static const uint32_t FK[4] = { 0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc };
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

// --- 工具函数 ---
static inline constexpr uint32_t move(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}
static inline constexpr uint32_t map(uint32_t n) {
    return n ^ move(n, 2) ^ move(n, 10) ^ move(n, 18) ^ move(n, 24);
}

static uint32_t T[256];
void init_T() {
    for (int i = 0; i < 256; i++) {
        uint32_t b = Sbox[i];
        T[i] = map((b << 24) | (b << 16) | (b << 8) | b);
    }
}
static inline uint32_t noliner(uint32_t a) {
    return ((uint32_t)Sbox[(a >> 24) & 0xFF] << 24)
         | ((uint32_t)Sbox[(a >> 16) & 0xFF] << 16)
         | ((uint32_t)Sbox[(a >> 8) & 0xFF] << 8)
         | Sbox[a & 0xFF];
}

// --- 密钥扩展 ---
void expand(const uint8_t key[16], uint32_t rk[32]) {
    uint32_t K[36];
    for (int i = 0; i < 4; i++) {
        K[i] = ((uint32_t)key[4 * i] << 24) | ((uint32_t)key[4 * i + 1] << 16)
             | ((uint32_t)key[4 * i + 2] << 8) | key[4 * i + 3];
        K[i] ^= FK[i];
    }
    for (int i = 0; i < 32; i++) {
        uint32_t tmp = K[i + 1] ^ K[i + 2] ^ K[i + 3] ^ CK[i];
        uint32_t buf = noliner(tmp);
        buf = buf ^ move(buf, 13) ^ move(buf, 23);
        rk[i] = K[i] ^ buf;
        K[i + 4] = rk[i];
    }
}

// --- 加密函数 ---
void encrypt(const uint8_t in[16], uint8_t out[16], const uint32_t rk[32]) {
    uint32_t r[4];
    for (int i = 0; i < 4; i++) {
        r[i] = ((uint32_t)in[i * 4] << 24)
             | ((uint32_t)in[i * 4 + 1] << 16)
             | ((uint32_t)in[i * 4 + 2] << 8)
             | in[i * 4 + 3];
    }

    for (int i = 0; i < 32; i++) {
        uint32_t tmp = r[1] ^ r[2] ^ r[3] ^ rk[i];
        uint32_t next = r[0] ^ T[(tmp >> 24) & 0xFF] ^ T[(tmp >> 16) & 0xFF]
                            ^ T[(tmp >> 8) & 0xFF] ^ T[tmp & 0xFF];
        r[0] = r[1];
        r[1] = r[2];
        r[2] = r[3];
        r[3] = next;
    }

    for (int i = 0; i < 4; i++) {
        uint32_t v = r[3 - i];
        out[i * 4] = (v >> 24) & 0xFF;
        out[i * 4 + 1] = (v >> 16) & 0xFF;
        out[i * 4 + 2] = (v >> 8) & 0xFF;
        out[i * 4 + 3] = v & 0xFF;
    }
}

struct u128 { uint64_t high, low; };

u128 GF128_mul(const u128& X, const u128& Y) {
    u128 Z = { 0, 0 };
    u128 V = X;

    for (int i = 0; i < 128; i++) {
        uint8_t y_bit = (Y.high >> (127 - i)) & 1;
        if (y_bit) {
            Z.high ^= V.high;
            Z.low ^= V.low;
        }

        bool carry = V.low & 1;
        V.low = (V.low >> 1) | (V.high << 63);
        V.high = V.high >> 1;
        if (carry) {
            V.high ^= 0xE100000000000000ULL;
        }
    }
    return Z;
}

u128 GHASH(const u128& H, const vector<uint8_t>& data) {
    u128 Y{ 0, 0 };
    const uint8_t* ptr = data.data();
    size_t blocks = data.size() / 16;

    for (size_t i = 0; i < blocks; i++) {
        u128 X{ 0, 0 };
        for (int j = 0; j < 8; j++) X.high = (X.high << 8) | ptr[j];
        for (int j = 0; j < 8; j++) X.low = (X.low << 8) | ptr[8 + j];
        ptr += 16;

        Y.high ^= X.high;
        Y.low ^= X.low;
        Y = GF128_mul(Y, H);
    }

    size_t rem = data.size() % 16;
    if (rem) {
        u128 X{ 0, 0 };
        for (size_t j = 0; j < rem; j++) {
            if (j < 8) X.high = (X.high << 8) | *ptr++;
            else X.low = (X.low << 8) | *ptr++;
        }
        X.high <<= (8 - rem % 8) * 8;
        Y.high ^= X.high;
        Y.low ^= X.low;
        Y = GF128_mul(Y, H);
    }
    return Y;
}

void count32(uint8_t counter[16]) {
    for (int i = 15; i >= 12; i--) {
        if (++counter[i]) break;
    }
}

void GCM(const uint32_t rk[32],
         const vector<uint8_t>& IV,
         const vector<uint8_t>& plaintext,
         vector<uint8_t>& ciphertext,
         uint8_t res[16])
{
    uint8_t zero_blk[16] = { 0 }, H_blk[16];
    encrypt(zero_blk, H_blk, rk);

    u128 H{ 0, 0 };
    for (int i = 0; i < 8; i++) H.high = (H.high << 8) | H_blk[i];
    for (int i = 0; i < 8; i++) H.low = (H.low << 8) | H_blk[8 + i];

    vector<uint8_t> count(16, 0);
    if (IV.size() == 12) {
        memcpy(count.data(), IV.data(), 12);
        count[15] = 1;
    } else {
        u128 hash_res = GHASH(H, IV);
        for (int i = 0; i < 8; i++) count[i] = (hash_res.high >> (56 - 8 * i)) & 0xFF;
        for (int i = 0; i < 8; i++) count[8 + i] = (hash_res.low >> (56 - 8 * i)) & 0xFF;
    }

    ciphertext.resize(plaintext.size());
    uint8_t CTR[16];
    memcpy(CTR, count.data(), 16);
    count32(CTR);

    for (size_t off = 0; off < plaintext.size(); off += 16) {
        uint8_t S[16];
        encrypt(CTR, S, rk);

        size_t block = min<size_t>(16, plaintext.size() - off);
        for (size_t i = 0; i < block; i++) {
            ciphertext[off + i] = plaintext[off + i] ^ S[i];
        }
        count32(CTR);
    }

    vector<uint8_t> auth_data = ciphertext;
    if (auth_data.size() % 16 != 0) {
        auth_data.resize((auth_data.size() + 15) / 16 * 16, 0);
    }

    uint64_t c_bits = ciphertext.size() * 8;
    for (int i = 0; i < 8; i++) auth_data.push_back(0);
    for (int i = 0; i < 8; i++) {
        auth_data.push_back((uint8_t)(c_bits >> (56 - 8 * i)));
    }

    u128 S_res = GHASH(H, auth_data);
    uint8_t E_count[16];
    encrypt(count.data(), E_count, rk);

    for (int i = 0; i < 16; i++) {
        res[i] = E_count[i] ^ (
            (i < 8) ? ((S_res.high >> (56 - 8 * i)) & 0xFF)
                    : ((S_res.low >> (120 - 8 * i)) & 0xFF)
        );
    }
}

// --- MAIN ---
int main() {
    init_T();

    uint32_t rk[32];
    expand(MK, rk);

    vector<uint8_t> IV(12);
    random_device rd;
    uniform_int_distribution<int> d(0, 255);
    for (auto& b : IV) b = d(rd);

    string s = "SDUCST";
    vector<uint8_t> pt(s.begin(), s.end()), ct, res(16);

    auto start = chrono::high_resolution_clock::now();
    GCM(rk, IV, pt, ct, res.data());
    auto end = chrono::high_resolution_clock::now();
    double time = chrono::duration<double, milli>(end - start).count();

    cout << "测试明文: " << s << endl;
    cout << "优化后GCM加密用时: " << time << " ms" << endl;
    cout << "认证标签: ";
    for (auto b : res) {
        cout << hex << setw(2) << setfill('0') << (int)b;
    }
    cout << endl;

    return 0;
}
