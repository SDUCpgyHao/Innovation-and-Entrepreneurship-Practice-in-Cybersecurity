/*
 * sm4_gcm.c
 *
 * SM4-GCM implementation (encrypt/decrypt) using SM4 block cipher from your project.
 *
 * - Uses SM4 block function via sm4_encrypt_block_aesni (or fallback basic) exposed in sm4.h.
 * - GHASH implemented with PCLMUL intrinsics when available; otherwise a portable (slow) fallback.
 *
 * Compile (MSYS2 / GCC, Ryzen 5800H):
 *   gcc -O3 -march=native -maes -mavx2 -mpclmul sm4_gcm.c sm4_basic.c sm4_optimized.c benchmark.c -o sm4_gcm_test
 *
 * API:
 *  int sm4_gcm_encrypt(const uint8_t key[16],
 *                      const uint8_t *iv, size_t iv_len,
 *                      const uint8_t *aad, size_t aad_len,
 *                      const uint8_t *pt, size_t pt_len,
 *                      uint8_t *ct, uint8_t tag[16]);
 *
 *  int sm4_gcm_decrypt(..., const uint8_t tag[16]); // returns 0 on success, -1 on tag mismatch
 *
 * Note: This file relies on sm4.h exposing an SM4 encrypt single-block function:
 *   void sm4_key_schedule_aesni(const uint8_t key[16], uint32_t rk[32]);
 *   void sm4_encrypt_block_aesni(uint8_t block[16], const uint32_t rk[32]);
 * and corresponding fallback functions if AES-NI is not present.
 *
 * Author: adapted for your project
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "sm4.h"

#ifdef __x86_64__
#include <cpuid.h>
#include <wmmintrin.h>   // AES intrinsics
#include <emmintrin.h>
#include <immintrin.h>
#include <x86intrin.h>
#endif

/* -------- helpers for 128-bit (big-endian) -------- */

/* load 16-byte big-endian into __m128i (treat bytes as network order) */
static inline __m128i load_be128(const uint8_t *b) {
#ifdef __SSE2__
    return _mm_loadu_si128((const __m128i*)b);
#else
    __m128i x; memcpy(&x, b, 16); return x;
#endif
}

/* store __m128i to 16 bytes (big-endian) */
static inline void store_be128(uint8_t *out, __m128i v) {
#ifdef __SSE2__
    _mm_storeu_si128((__m128i*)out, v);
#else
    memcpy(out, &v, 16);
#endif
}

/* xor two 128-bit lanes: a ^= b */
static inline __m128i xor128(__m128i a, __m128i b) {
    return _mm_xor_si128(a, b);
}

/* set zero */
static inline __m128i zero128(void) {
    return _mm_setzero_si128();
}

/* swap bytes to/from big-endian <-> little-endian if needed:
   intrinsics treat memory order as bytes; we keep everything as byte arrays,
   so we don't do byte swapping here. We'll ensure GHASH math uses bit-level
   correct representation consistent with GCM spec (treat block as 128-bit
   unsigned integer with bytes in big-endian). */

/* -------- GHASH: multiplication in GF(2^128) --------
   We implement two variants:
     - pclmul (intrinsics) for speed (preferred on Ryzen 5800H)
     - portable bitwise fallback (slow but correct)
*/

/* convert 16-byte array (big-endian) into two 64-bit halves (hi, lo) as uint64_t big-endian */
static inline void be16_to_u64(const uint8_t b[16], uint64_t *hi, uint64_t *lo) {
    uint64_t a = 0, c = 0;
    for (int i = 0; i < 8; i++) a = (a << 8) | b[i];
    for (int i = 8; i < 16; i++) c = (c << 8) | b[i];
    *hi = a; *lo = c;
}

/* convert two uint64_t hi,lo big-endian into 16-byte array */
static inline void u64_to_be16(uint8_t out[16], uint64_t hi, uint64_t lo) {
    for (int i = 7; i >= 0; i--) { out[i] = hi & 0xFF; hi >>= 8; }
    for (int i = 15; i >= 8; i--) { out[i] = lo & 0xFF; lo >>= 8; }
}

/* portable carry-less multiplication: c = a * b in GF(2)[x] (128-bit words)
   a, b are arrays of 16 bytes big-endian */
static void gf128_mul_portable(const uint8_t a[16], const uint8_t b[16], uint8_t out[16]) {
    /* Represent as 128-bit bitstrings, do schoolbook carryless multiplication.
       We'll treat a, b as big-endian bits. Use bit-by-bit method (slow). */
    uint8_t Z[16] = {0};
    uint8_t V[16];
    memcpy(V, b, 16); /* V = b */
    /* for i from 0 to 127: if a_bit_i == 1 then Z ^= V; V <<= 1 */
    for (int byte = 0; byte < 16; ++byte) {
        for (int bit = 7; bit >= 0; --bit) {
            int a_bit = (a[byte] >> bit) & 1;
            if (a_bit) {
                for (int k=0;k<16;k++) Z[k] ^= V[k];
            }
            /* V = V << 1 (big-endian shift left) */
            int carry = 0;
            for (int k = 15; k >= 0; --k) {
                int new_carry = (V[k] >> 7) & 1;
                V[k] = (uint8_t)((V[k] << 1) | carry);
                carry = new_carry;
            }
        }
    }
    /* Now Z is 256-bit product (in lower 16 bytes?) Actually we performed moduloless multiplication
       producing 256-bit result in Z as 128-bit (since we shifted V only 128 times).
       But easier: our routine above is correct produce 128-bit polynomial product,
       next we must reduce modulo the GCM polynomial: x^128 + x^7 + x^2 + x + 1
       However since GCM reduction requires 256-bit intermediate, the portable routine here
       is oversimplified. To be safe and correct, implement portable as bitwise long multiplication
       producing 256-bit then reduce. We'll implement clearer approach below. */
    /* FALLBACK: use slower but correct bit-by-bit 256-bit accumulation with reductions on the fly */
    uint8_t Z2[32];
    memset(Z2, 0, 32);
    /* b as bitstring little-endian? We'll transform to big-endian bit order handling carefully */
    /* Let's do this simpler: treat bits MSB-first: for i in 0..127:
         if (a_bit_i) XOR Z2[i..i+127] ^= b[0..127]
       Then reduce Z2 (256-bit) modulo R(x).
    */
    memset(Z2, 0, 32);
    for (int i=0;i<128;i++) {
        int byte_idx = i / 8;
        int bit_idx = 7 - (i % 8); /* MSB-first */
        int abit = (a[byte_idx] >> bit_idx) & 1;
        if (abit) {
            /* XOR b into Z2 starting at bit position i */
            for (int j=0;j<128;j++) {
                int bbyte = j / 8;
                int bbit = 7 - (j % 8);
                int bbitv = (b[bbyte] >> bbit) & 1;
                if (bbitv) {
                    int pos = i + j; /* 0..255 */
                    int pos_byte = pos / 8;
                    int pos_bit = 7 - (pos % 8);
                    Z2[pos_byte] ^= (1u << pos_bit);
                }
            }
        }
    }
    /* Reduce Z2 (256-bit) modulo x^128 + x^7 + x^2 + x + 1.
       That is, for bits at positions >=128, fold them:
         For each bit i from 255 down to 128:
           if Z2[i] == 1: clear it and XOR to positions i-128 + {7,2,1,0} and i-128 (i.e. shift)
       We'll implement straightforward loop.
    */
    for (int pos = 255; pos >= 128; --pos) {
        int pb = pos / 8;
        int bit = 7 - (pos % 8);
        if ((Z2[pb] >> bit) & 1) {
            /* clear */
            Z2[pb] &= ~(1u << bit);
            int base = pos - 128;
            /* XOR at base + 0 */
            int bpos = base;
            Z2[bpos / 8] ^= (1u << (7 - (bpos % 8)));
            /* XOR at base + 1 */
            bpos = base + 1;
            Z2[bpos / 8] ^= (1u << (7 - (bpos % 8)));
            /* XOR at base + 2 */
            bpos = base + 2;
            Z2[bpos / 8] ^= (1u << (7 - (bpos % 8)));
            /* XOR at base + 7 */
            bpos = base + 7;
            Z2[bpos / 8] ^= (1u << (7 - (bpos % 8)));
        }
    }
    /* result is lower 128 bits Z2[0..15] */
    for (int i=0;i<16;i++) out[i] = Z2[i];
}

/* Use PCLMUL intrinsics (x86) for fast multiplication and reduce.
   Compute Z = a * b, a,b 128-bit big-endian represented in __m128i.
   We will follow standard GHASH CLMUL reduction technique.
*/
#ifdef __PCLMUL__
static inline __m128i mm_loadu(const uint8_t *p) {
    return _mm_loadu_si128((const __m128i *)p);
}
static inline void mm_storeu(uint8_t *p, __m128i v) {
    _mm_storeu_si128((__m128i*)p, v);
}

/* carryless multiply of two 128-bit values (as __m128i) producing 256-bit
   result stored into two __m128i: (hi, lo) where hi holds most-significant 128 bits.
*/
static inline void clmul_128(__m128i a, __m128i b, __m128i *hi, __m128i *lo) {
    __m128i a0 = a;
    __m128i b0 = b;

    __m128i a_lo = _mm_unpacklo_epi64(a0, a0); // not needed
    /* perform CLMUL: use three 64x64 clmul to assemble 128x128 */
    __m128i t1 = _mm_clmulepi64_si128(a0, b0, 0x00); /* lo-lo */
    __m128i t2 = _mm_clmulepi64_si128(a0, b0, 0x11); /* hi-hi */
    __m128i t3 = _mm_clmulepi64_si128(a0, b0, 0x10); /* hi-lo */
    __m128i t4 = _mm_clmulepi64_si128(a0, b0, 0x01); /* lo-hi */

    __m128i mid = _mm_xor_si128(t3, t4);

    /* assemble 256-bit = t2 || t1 with mid added into middle */
    /* lo = t1 ^ (mid << 64) */
    __m128i mid_shl = _mm_slli_si128(mid, 8);
    __m128i lo_res = _mm_xor_si128(t1, mid_shl);
    /* hi = t2 ^ (mid >> 64) */
    __m128i mid_shr = _mm_srli_si128(mid, 8);
    __m128i hi_res = _mm_xor_si128(t2, mid_shr);

    *hi = hi_res;
    *lo = lo_res;
}

/* reduce 256-bit product (hi,lo) modulo the GCM polynomial (x^128 + x^7 + x^2 + x + 1)
   returns 128-bit result.
   Algorithm adapted from Intel GHASH implementations using CLMUL.
*/
static inline __m128i clmul_reduce(__m128i hi, __m128i lo) {
    /* Reduction constants */
    const __m128i R = _mm_set_epi32(0x00000000, 0x00000000, 0x00000000, 0xE1000000); // for AES-GCM (but endianness sensitive)
    /* However constructing reduction is delicate due to endianness; rather than re-derive,
       follow known sequence:
       Let Z = hi || lo (256 bits). We want X = Z mod P(x).
       Use method: V = hi >> 1 ? We'll follow existing pattern:
       See e.g. Intel whitepaper / GHASH reference implementations.
    */
    /* Simpler implementation: convert hi||lo to 32-byte array, perform bit-wise reduction
       using byte operations - still faster than portable bit loops due to vector ops.
       But to keep code concise and correct, fall back to extracting to bytes and using portable reduction.
    */
    uint8_t Z[32];
    _mm_storeu_si128((__m128i*)(Z+16), hi); // store hi at Z[16..31]
    _mm_storeu_si128((__m128i*)(Z+0), lo);  // store lo at Z[0..15]
    /* Now perform reduction similar to portable approach but operate on bytes */
    /* For pos from 255 down to 128: if bit set, fold to lower words */
    for (int pos=255; pos>=128; --pos) {
        int byte_idx = pos / 8;
        int bit_idx = 7 - (pos % 8);
        if ((Z[byte_idx] >> bit_idx) & 1) {
            Z[byte_idx] &= ~(1u << bit_idx);
            int base = pos - 128;
            /* XOR at base + 0,1,2,7 */
            int ps = base;
            Z[ps/8] ^= (1u << (7 - (ps%8)));
            ps = base + 1;
            Z[ps/8] ^= (1u << (7 - (ps%8)));
            ps = base + 2;
            Z[ps/8] ^= (1u << (7 - (ps%8)));
            ps = base + 7;
            Z[ps/8] ^= (1u << (7 - (ps%8)));
        }
    }
    __m128i res = _mm_loadu_si128((const __m128i*)Z); /* lower 16 bytes */
    return res;
}

/* full multiplication with clmul and reduce: res = (a * b) mod P */
static inline __m128i gf_mul_clmul_128(__m128i a, __m128i b) {
    __m128i hi, lo;
    clmul_128(a, b, &hi, &lo);
    return clmul_reduce(hi, lo);
}

/* wrapper: multiply two 16-byte arrays using CLMUL -> output 16 bytes */
static void gf128_mul_clmul(const uint8_t a[16], const uint8_t b[16], uint8_t out[16]) {
    __m128i va = _mm_loadu_si128((const __m128i*)a);
    __m128i vb = _mm_loadu_si128((const __m128i*)b);
    __m128i r = gf_mul_clmul_128(va, vb);
    _mm_storeu_si128((__m128i*)out, r);
}
#endif /* __PCLMUL__ */

/* runtime capability detection for pclmul */
static int cpu_supports_pclmul(void) {
#ifdef __x86_64__
    unsigned int eax, ebx, ecx, edx;
    if (!__get_cpuid(1, &eax, &ebx, &ecx, &edx)) return 0;
    /* PCLMUL bit is ECX bit 1 (bit_PCLMUL) */
    return (ecx & bit_PCLMUL) != 0;
#else
    return 0;
#endif
}

/* wrapper: multiply a and b produce out, choose fastest available implementation */
static void gf128_mul(const uint8_t a[16], const uint8_t b[16], uint8_t out[16]) {
#if defined(__PCLMUL__) || defined(__PCLMUL)
    if (cpu_supports_pclmul()) {
#ifdef __PCLMUL__
        gf128_mul_clmul(a,b,out);
        return;
#else
        /* if compile-time intrinsics not available, fall back */
#endif
    }
#endif
    gf128_mul_portable(a,b,out);
}

/* GHASH state: X (current 128-bit auth value) and H (hash subkey) */
typedef struct {
    uint8_t H[16];   /* hash key H = E_K(0^128) */
    uint8_t X[16];   /* current accumulator */
} ghash_ctx_t;

static void ghash_init(ghash_ctx_t *ctx, const uint8_t H[16]) {
    memcpy(ctx->H, H, 16);
    memset(ctx->X, 0, 16);
}

/* GHASH: process single 16-byte block (Y), X = (X xor Y) * H */
static void ghash_update_block(ghash_ctx_t *ctx, const uint8_t Y[16]) {
    uint8_t t[16];
    for (int i=0;i<16;i++) t[i] = ctx->X[i] ^ Y[i];
    gf128_mul(t, ctx->H, ctx->X);
}

/* GHASH: process arbitrary length buffer (multiple of 16 bytes); for last partial block,
   caller must pad with zeros to 16 bytes and call this function. */
static void ghash_update(ghash_ctx_t *ctx, const uint8_t *data, size_t len) {
    size_t i = 0;
    uint8_t buf[16];
    for (; i + 16 <= len; i += 16) {
        ghash_update_block(ctx, &data[i]);
    }
    if (i < len) {
        memset(buf, 0, 16);
        size_t rem = len - i;
        memcpy(buf, &data[i], rem);
        ghash_update_block(ctx, buf);
    }
}

/* finalization: process lengths (len_a, len_c) both 64-bit values in bits, concatenated as 128-bit BE */
static void ghash_finalize(ghash_ctx_t *ctx, uint64_t aad_bits, uint64_t ct_bits) {
    uint8_t lenblock[16];
    /* store aad_bits (64-bit big-endian) then ct_bits big-endian */
    for (int i=0;i<8;i++) lenblock[i] = (uint8_t)( (aad_bits >> (56 - 8*i)) & 0xFF );
    for (int i=0;i<8;i++) lenblock[8+i] = (uint8_t)( (ct_bits >> (56 - 8*i)) & 0xFF );
    ghash_update_block(ctx, lenblock);
}

/* -------- GCM helper: increment counter (32-bit) on last 32 bits big-endian -------- */
static void inc32(uint8_t counter[16]) {
    /* increment last 32 bits (big-endian) */
    for (int i = 15; i >= 12; --i) {
        if (++counter[i]) break;
    }
}

/* compute J0 from IV:
   if iv_len == 12: J0 = IV || 0x00000001
   else: J0 = GHASH(H, IV || pad) where lengths appended later
*/
static void compute_j0(const uint8_t *iv, size_t iv_len, const uint8_t H[16], uint8_t J0[16]) {
    if (iv_len == 12) {
        memcpy(J0, iv, 12);
        J0[12] = 0x00; J0[13] = 0x00; J0[14] = 0x00; J0[15] = 0x01;
    } else {
        ghash_ctx_t ctx;
        ghash_init(&ctx, H);
        ghash_update(&ctx, iv, iv_len);
        /* pad to 128-bit boundary already performed by ghash_update */
        /* finalize with lengths: len(IV) * 8, len(0) * 8 (ciphertext len 0 here) */
        ghash_finalize(&ctx, (uint64_t)iv_len * 8ULL, 0ULL);
        memcpy(J0, ctx.X, 16);
    }
}

/* get block cipher E(K, block) using available SM4 implementation.
   We choose AES-NI optimized path if sm4_cpu_support_aesni() returns true,
   otherwise use basic block encrypt.
*/
static void sm4_block_encrypt_chosen(const uint8_t key[16], const uint32_t rk[SM4_RK_LEN], const uint8_t in[16], uint8_t out[16]) {
    uint8_t tmp[16];
    memcpy(tmp, in, 16);
    if (sm4_cpu_support_aesni()) {
        /* use AES-NI SM4 implementation */
        sm4_encrypt_block_aesni(tmp, rk);
    } else {
        /* fallback: basic */
        sm4_encrypt_block_basic(tmp, rk);
    }
    memcpy(out, tmp, 16);
}

/* ---------- Public SM4-GCM API ---------- */

/* Return 0 on success, -1 on error */
int sm4_gcm_encrypt(const uint8_t key[16],
                    const uint8_t *iv, size_t iv_len,
                    const uint8_t *aad, size_t aad_len,
                    const uint8_t *pt, size_t pt_len,
                    uint8_t *ct, uint8_t tag[16]) {
    if (!key || !iv || (!pt && pt_len>0) || (!ct && pt_len>0)) return -1;

    uint32_t rk[SM4_RK_LEN];
    /* choose key schedule routine similarly: sm4_key_schedule_aesni exists and identical rk values */
    sm4_key_schedule_aesni(key, rk);

    /* compute H = E_K(0^128) */
    uint8_t zero_block[16] = {0};
    uint8_t H[16];
    sm4_block_encrypt_chosen(key, rk, zero_block, H);

    /* compute J0 */
    uint8_t J0[16];
    compute_j0(iv, iv_len, H, J0);

    /* prepare GHASH context (for AAD and ciphertext) */
    ghash_ctx_t gctx;
    ghash_init(&gctx, H);

    /* process AAD */
    if (aad_len > 0) ghash_update(&gctx, aad, aad_len);

    /* encrypt: produce ciphertext and GHASH over ciphertext */
    uint8_t ctr[16];
    memcpy(ctr, J0, 16);
    inc32(ctr); /* initial counter for first block */

    size_t i = 0;
    uint8_t keystream[16];
    uint8_t buf[16];
    for (i = 0; i + 16 <= pt_len; i += 16) {
        sm4_block_encrypt_chosen(key, rk, ctr, keystream);
        for (int j=0;j<16;j++) {
            ct[i+j] = pt[i+j] ^ keystream[j];
        }
        /* GHASH update with ciphertext block */
        ghash_update_block(&gctx, &ct[i]);
        inc32(ctr);
    }
    /* final partial */
    if (i < pt_len) {
        size_t rem = pt_len - i;
        sm4_block_encrypt_chosen(key, rk, ctr, keystream);
        for (size_t j=0;j<rem;j++) ct[i+j] = pt[i+j] ^ keystream[j];
        /* pad ciphertext partial block with zeros for GHASH */
        memset(buf, 0, 16);
        memcpy(buf, &ct[i], rem);
        ghash_update_block(&gctx, buf);
    }

    /* finalize GHASH with lengths: aad_bits, ct_bits */
    uint64_t aad_bits = (uint64_t)aad_len * 8ULL;
    uint64_t ct_bits = (uint64_t)pt_len * 8ULL;
    ghash_finalize(&gctx, aad_bits, ct_bits);

    /* compute E_K(inc32(J0)) */
    uint8_t S[16];
    uint8_t J0_inc[16];
    memcpy(J0_inc, J0, 16);
    inc32(J0_inc);
    sm4_block_encrypt_chosen(key, rk, J0_inc, S);

    /* tag = S xor GHASH */
    for (int k=0;k<16;k++) tag[k] = S[k] ^ gctx.X[k];

    return 0;
}

/* decrypt: returns 0 if tag matches and decryption ok, -1 if tag mismatch or error */
int sm4_gcm_decrypt(const uint8_t key[16],
                    const uint8_t *iv, size_t iv_len,
                    const uint8_t *aad, size_t aad_len,
                    const uint8_t *ct, size_t ct_len,
                    uint8_t *pt, const uint8_t tag[16]) {
    if (!key || !iv || (!ct && ct_len>0) || (!pt && ct_len>0) || !tag) return -1;

    uint32_t rk[SM4_RK_LEN];
    sm4_key_schedule_aesni(key, rk);

    /* H = E_K(0) */
    uint8_t zero_block[16] = {0};
    uint8_t H[16];
    sm4_block_encrypt_chosen(key, rk, zero_block, H);

    /* J0 */
    uint8_t J0[16];
    compute_j0(iv, iv_len, H, J0);

    /* GHASH over AAD||C */
    ghash_ctx_t gctx;
    ghash_init(&gctx, H);
    if (aad_len > 0) ghash_update(&gctx, aad, aad_len);
    /* process ciphertext blocks */
    size_t i = 0;
    uint8_t buf[16];
    for (i=0;i+16 <= ct_len; i+=16) {
        ghash_update_block(&gctx, &ct[i]);
    }
    if (i < ct_len) {
        size_t rem = ct_len - i;
        memset(buf, 0, 16);
        memcpy(buf, &ct[i], rem);
        ghash_update_block(&gctx, buf);
    }
    /* finalize GHASH */
    uint64_t aad_bits = (uint64_t)aad_len * 8ULL;
    uint64_t ct_bits = (uint64_t)ct_len * 8ULL;
    ghash_finalize(&gctx, aad_bits, ct_bits);

    /* compute S = E_K(inc32(J0)) */
    uint8_t J0_inc[16], S[16];
    memcpy(J0_inc, J0, 16); inc32(J0_inc);
    sm4_block_encrypt_chosen(key, rk, J0_inc, S);

    /* compute expected tag = S xor GHASH */
    uint8_t expected[16];
    for (int k=0;k<16;k++) expected[k] = S[k] ^ gctx.X[k];

    /* compare tags in constant time */
    uint8_t diff = 0;
    for (int k=0;k<16;k++) diff |= (expected[k] ^ tag[k]);
    if (diff != 0) {
        /* tag mismatch */
        return -1;
    }

    /* tags ok -> produce plaintext: decrypt by XORing keystream */
    /* generate keystream and XOR */
    uint8_t ctr[16];
    memcpy(ctr, J0, 16); inc32(ctr);
    uint8_t keystream[16];
    size_t pos = 0;
    for (pos=0; pos+16 <= ct_len; pos += 16) {
        sm4_block_encrypt_chosen(key, rk, ctr, keystream);
        for (int j=0;j<16;j++) pt[pos+j] = ct[pos+j] ^ keystream[j];
        inc32(ctr);
    }
    if (pos < ct_len) {
        size_t rem = ct_len - pos;
        sm4_block_encrypt_chosen(key, rk, ctr, keystream);
        for (size_t j=0;j<rem;j++) pt[pos+j] = ct[pos+j] ^ keystream[j];
    }
    return 0;
}