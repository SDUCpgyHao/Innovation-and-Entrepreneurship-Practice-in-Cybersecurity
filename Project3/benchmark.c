#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include "sm3_basic.h"

void print_hex(const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

int main() {
    const int TIMES = 10000;
    const char *test_message = "abc";
    size_t len = strlen(test_message);
    uint8_t hash[32];

    clock_t start = clock();
    for (int i = 0; i < TIMES; i++) {
        sm3_basic((const uint8_t *)test_message, len, hash);
    }
    clock_t end = clock();

    printf("SM3 basic hash of 'abc':\n");
    print_hex(hash, 32);

    double elapsed = (double)(end - start) / CLOCKS_PER_SEC;
    printf("Average time: %.6f ms\n", 1000.0 * elapsed / TIMES);

    return 0;
}