#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include "sm3_basic.h"
#include "sm3_optimized.h"

void print_hex(const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

double benchmark(void (*hash_func)(const uint8_t *, size_t, uint8_t *), const char *name, const char *input, int times) {
    uint8_t hash[32];
    size_t len = strlen(input);
    clock_t start = clock();
    for (int i = 0; i < times; i++) {
        hash_func((const uint8_t *)input, len, hash);
    }
    clock_t end = clock();
    double elapsed = (double)(end - start) / CLOCKS_PER_SEC;
    printf("[%s] Sample hash: ", name);
    print_hex(hash, 32);
    printf("[%s] Time: %.6f ms (avg over %d)\n", name, 1000.0 * elapsed / times, times);
    return elapsed;
}

int main() {
    const int TIMES = 100000;
    const char *test_message = "abc";

    printf("Benchmarking SM3 Implementations...\n");
    double t_basic = benchmark(sm3_basic, "Basic", test_message, TIMES);
    double t_macro = benchmark(sm3_optimized_macro, "Macro", test_message, TIMES);
    double t_unroll = benchmark(sm3_optimized_unroll, "Unroll", test_message, TIMES);
    double t_simd = benchmark(sm3_optimized_simd, "SIMD", test_message, TIMES);

    printf("\n--- Speedup Compared to Basic ---\n");
    printf("Macro:  %.2fx faster\n", t_basic / t_macro);
    printf("Unroll: %.2fx faster\n", t_basic / t_unroll);
    printf("SIMD:   %.2fx faster\n", t_basic / t_simd);

    return 0;
}