/* ecc-sign.c
 *
 * Copyright (C) 2006-2020 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */


#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>

#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/wc_port.h>

#define MAX_FIRMWARE_LEN (1024 * 1024)
static const int gFwLen = MAX_FIRMWARE_LEN;
static const int gFwChunkLen = 128;
static byte gFwBuf[MAX_FIRMWARE_LEN];
static const int gSignTimes = 1;

//#define ENABLE_BUF_PRINT
#define ECC_KEY_SIZE  32
#define ECC_KEY_CURVE ECC_SECP256R1

/* func_args from test.h, so don't have to pull in other stuff */
typedef struct func_args {
    int    argc;
    char** argv;
    int    return_code;
} func_args;

#ifdef ENABLE_BUF_PRINT
static void PrintBuffer(const byte* buffer, word32 length)
{
    #define LINE_LEN 16
    word32 i;
    char line[80];

    if (!buffer) {
        printf("\tNULL");
        return;
    }

    sprintf(line, "\t");

    for (i = 0; i < LINE_LEN; i++) {
        if (i < length)
            sprintf(line + 1 + i * 3,"%02x ", buffer[i]);
        else
            sprintf(line + 1 + i * 3, "   ");
    }

    sprintf(line + 1 + LINE_LEN * 3, "| ");

    for (i = 0; i < LINE_LEN; i++)
        if (i < length)
            sprintf(line + 3 + LINE_LEN * 3 + i,
                 "%c", 31 < buffer[i] && buffer[i] < 127 ? buffer[i] : '.');

    puts(line);

    if (length > LINE_LEN)
        PrintBuffer(buffer + LINE_LEN, length - LINE_LEN);
}
#endif

static int HashFirmware(byte* hashBuf)
{
    int ret;
    wc_Sha256 sha;
    int idx = 0, len = gFwLen, sz;

    ret = wc_InitSha256(&sha);
    if (ret != 0)
        return ret;

    /* loop through each chunk of firmware */
    while (len > 0) {
        /* determine hash update size */
        sz = len;
        if (sz > gFwChunkLen)
            sz = gFwChunkLen;

        /* update hash */
        ret = wc_Sha256Update(&sha, &gFwBuf[idx], (word32)sz);
        if (ret != 0)
            break;

        len -= sz;
        idx += sz;
    }

    if (ret == 0) {
        ret = wc_Sha256Final(&sha, hashBuf);
    }

    wc_Sha256Free(&sha);

    return ret;
}

#include <wolfssl/wolfcrypt/mem_track.h>

#ifdef WOLFSSL_TRACK_MEMORY_VERBOSE
static long heap_baselineAllocs;
static long heap_baselineBytes;

#define PRINT_HEAP_INIT() { \
    (void)wolfCrypt_heap_peakAllocs_checkpoint();                \
    heap_baselineAllocs = wolfCrypt_heap_peakAllocs_checkpoint();\
    (void)wolfCrypt_heap_peakBytes_checkpoint();                 \
    heap_baselineBytes = wolfCrypt_heap_peakBytes_checkpoint();  \
}

#define PRINT_HEAP_CHECKPOINT() {                                            \
    const ssize_t _rha = wolfCrypt_heap_peakAllocs_checkpoint() - heap_baselineAllocs; \
    const ssize_t _rhb = wolfCrypt_heap_peakBytes_checkpoint() - heap_baselineBytes;   \
    printf("    relative heap peak usage: %ld alloc%s, %ld bytes\n",         \
           (long int)_rha,                                                   \
           _rha == 1 ? "" : "s",                                             \
           (long int)_rhb);                                                  \
    heap_baselineAllocs = wolfCrypt_heap_peakAllocs_checkpoint();            \
    heap_baselineBytes = wolfCrypt_heap_peakBytes_checkpoint();              \
    }
#else
#define PRINT_HEAP_INIT() WC_DO_NOTHING
#define PRINT_HEAP_CHECKPOINT() WC_DO_NOTHING
#endif

#ifdef HAVE_STACK_SIZE_VERBOSE
#define TEST_CHECKPOINT(...) {                              \
    STACK_SIZE_CHECKPOINT(printf(__VA_ARGS__));             \
    PRINT_HEAP_CHECKPOINT();                                \
}
#else
#define TEST_CHECKPOINT(...) WC_DO_NOTHING
#endif


static int SignFirmware(byte* hashBuf, word32 hashLen, byte* sigBuf, word32* sigLen)
{
    int ret = 0;
    WC_RNG rng;
    ecc_key key;

    TEST_CHECKPOINT("SignFirmware: Start\n");

    ret = wc_InitRng(&rng);
    if (ret != 0)
        return ret;
    TEST_CHECKPOINT("SignFirmware: InitRNG\n");

    /* generate key for testing if one hasn't been created */
    ret = wc_ecc_init(&key);
    if (ret == 0) {
        ret = wc_ecc_make_key_ex(&rng, ECC_KEY_SIZE, &key, ECC_KEY_CURVE);
        if (ret == 0) {
            printf("KeyGen Done\n");
        }
    }
    TEST_CHECKPOINT("SignFirmware: MakeKey\n");

    /* sign hash */
    if (ret == 0) {
        ret = wc_ecc_sign_hash(hashBuf, hashLen, sigBuf, sigLen, &rng, &key);
        TEST_CHECKPOINT("SignFirmware: Sign\n");
        printf("Sign ret %d, sigLen %d\n", ret, *sigLen);
    }
    if (ret == 0) {
        int is_valid_sig = 0;
        ret = wc_ecc_verify_hash(sigBuf, *sigLen, hashBuf, hashLen,
            &is_valid_sig, &key);
        TEST_CHECKPOINT("SignFirmware: Verify\n");
        printf("Verify ret %d, is_valid_sig %d\n", ret, is_valid_sig);
    }

    wc_FreeRng(&rng);
    wc_ecc_free(&key);

    return ret;
}

#ifdef HAVE_STACK_SIZE
THREAD_RETURN WOLFSSL_THREAD ecc_test(void* args)
#else
wc_test_ret_t ecc_test(void* args)
#endif
{
    int ret;
    byte hashBuf[WC_SHA256_DIGEST_SIZE];
    word32 hashLen = WC_SHA256_DIGEST_SIZE;
    byte sigBuf[ECC_MAX_SIG_SIZE];
    word32 sigLen = ECC_MAX_SIG_SIZE;
    int i;

    STACK_SIZE_INIT();
    PRINT_HEAP_INIT();

    /* init bogus firmware */
    for (i=0; i<gFwLen; i++) {
        gFwBuf[i] = (byte)i;
    }

    /* try performing signature a few times */
    for (i=0; i < gSignTimes; i++) {
        memset(hashBuf, 0, hashLen);
        ret = HashFirmware(hashBuf);
        if (ret == 0) {
            sigLen = ECC_MAX_SIG_SIZE;
            memset(sigBuf, 0, sigLen);
            ret = SignFirmware(hashBuf, hashLen, sigBuf, &sigLen);
        }

        printf("Firmware Signature %d: Ret %d, HashLen %d, SigLen %d\n", i, ret, hashLen, sigLen);

    #ifdef ENABLE_BUF_PRINT
        PrintBuffer(hashBuf, hashLen);
        printf("\n");
        PrintBuffer(sigBuf, sigLen);
    #endif
    }
    EXIT_TEST(ret);
}

int main(int argc, char** argv)
{
    func_args args = { 0, 0, 0 };

    args.argc = argc;
    args.argv = argv;

    wolfCrypt_Init();

#ifdef HAVE_STACK_SIZE
    StackSizeCheck(&args, ecc_test);
#else
    ecc_test(&args);
#endif

    wolfCrypt_Cleanup();

    return args.return_code;
}
