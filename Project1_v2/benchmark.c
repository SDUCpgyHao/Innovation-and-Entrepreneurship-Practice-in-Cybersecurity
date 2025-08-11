#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include "sm4.h"
#include "sm4_gcm.h"

#define TEST_ITERATIONS 1000000
#define LARGE_TEST_SIZE (16 * 1024) // 16KB

// Helper function to print time and speedup
static void print_result(const char *name, clock_t start, clock_t end, 
                         clock_t baseline_time, size_t bytes_processed) {
    double elapsed = (double)(end - start) / CLOCKS_PER_SEC;
    double speed = (double)bytes_processed / (1024 * 1024) / elapsed; // MB/s
    double speedup = (baseline_time > 0) ? (double)baseline_time / (end - start) : 1.0;
    
    printf("%-15s: %.3f sec (%.2f MB/s)", name, elapsed, speed);
    if (baseline_time > 0) {
        printf(", speedup: %.2fx", speedup);
    }
    printf("\n");
}

// Test a single block encryption function
static void test_block_encrypt(const char *name, 
                              void (*encrypt_func)(uint8_t[16], const uint32_t[SM4_RK_LEN]),
                              const uint32_t rk[SM4_RK_LEN], 
                              clock_t baseline_time) {
    uint8_t block[16] = {0};
    clock_t start = clock();
    
    for (int i = 0; i < TEST_ITERATIONS; i++) {
        encrypt_func(block, rk);
    }
    
    clock_t end = clock();
    print_result(name, start, end, baseline_time, TEST_ITERATIONS * 16);
}

// Test multi-block encryption (for AES-NI vectorized version)
static void test_blocks_encrypt(const char *name,
                               void (*encrypt_func)(uint8_t *, const uint32_t[SM4_RK_LEN]),
                               const uint32_t rk[SM4_RK_LEN],
                               clock_t baseline_time) {
    uint8_t blocks[4 * 16] = {0};
    clock_t start = clock();
    
    for (int i = 0; i < TEST_ITERATIONS; i++) {
        encrypt_func(blocks, rk);
    }
    
    clock_t end = clock();
    print_result(name, start, end, baseline_time, TEST_ITERATIONS * 4 * 16);
}

// Test large buffer encryption with GCM
static void test_gcm_encrypt(const char *name, size_t size) {
    uint8_t key[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                       0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};
    uint8_t iv[12] = {0};
    uint8_t aad[16] = {0};
    uint8_t pt[LARGE_TEST_SIZE] = {0};
    uint8_t ct[LARGE_TEST_SIZE] = {0};
    uint8_t tag[16] = {0};
    
    clock_t start = clock();
    
    for (int i = 0; i < TEST_ITERATIONS / 10; i++) {
        sm4_gcm_encrypt(key, iv, sizeof(iv), aad, sizeof(aad), 
                       pt, size, ct, tag);
    }
    
    clock_t end = clock();
    print_result(name, start, end, 0, (TEST_ITERATIONS / 10) * size);
}

int main() {
    uint8_t key[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                       0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};
    uint32_t rk[SM4_RK_LEN] = {0};
    
    printf("=== SM4 Benchmark ===\n");
    printf("CPU support: AES-NI=%d, GFNI=%d\n", 
           sm4_cpu_support_aesni(), sm4_cpu_support_gfni());
    
    // Generate round keys once for all tests
    sm4_key_schedule_basic(key, rk);
    
    printf("\n=== Single Block Encryption (16 bytes) ===\n");
    printf("Testing %d iterations\n", TEST_ITERATIONS);
    
    // Test basic implementation first to get baseline
    clock_t basic_start = clock();
    for (int i = 0; i < TEST_ITERATIONS; i++) {
        uint8_t block[16] = {0};
        sm4_encrypt_block_basic(block, rk);
    }
    clock_t basic_end = clock();
    clock_t baseline_time = basic_end - basic_start;
    print_result("basic", basic_start, basic_end, 0, TEST_ITERATIONS * 16);
    
    // Test other implementations
    test_block_encrypt("t-table", sm4_encrypt_block_ttable, rk, baseline_time);
    test_block_encrypt("AES-NI", sm4_encrypt_block_aesni, rk, baseline_time);
    test_block_encrypt("GFNI", sm4_encrypt_block_gfni, rk, baseline_time);
    
    printf("\n=== Multi-Block Encryption (4x16 bytes) ===\n");
    printf("Testing %d iterations\n", TEST_ITERATIONS);
    test_blocks_encrypt("AES-NI 4x", sm4_encrypt_blocks_aesni, rk, baseline_time * 4);
    
    printf("\n=== GCM Encryption (16KB) ===\n");
    printf("Testing %d iterations\n", TEST_ITERATIONS / 10);
    test_gcm_encrypt("SM4-GCM", LARGE_TEST_SIZE);
    
    return 0;
}