/* slh_dsa.c
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
 *
 * This file is part of wolfSSL. (formerly known as CyaSSL)
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

/* Example of SLH-DSA (FIPS 205) key generation, signing and verifying. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/wc_slhdsa.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#ifdef WOLFSSL_HAVE_SLHDSA

struct param_map_t {
    const char*      name;
    enum SlhDsaParam param;
};

static const struct param_map_t param_map[] = {
    { "shake-128s", SLHDSA_SHAKE128S },
    { "shake-128f", SLHDSA_SHAKE128F },
    { "shake-192s", SLHDSA_SHAKE192S },
    { "shake-192f", SLHDSA_SHAKE192F },
    { "shake-256s", SLHDSA_SHAKE256S },
    { "shake-256f", SLHDSA_SHAKE256F },
#ifdef WOLFSSL_SLHDSA_SHA2
    { "sha2-128s",  SLHDSA_SHA2_128S },
    { "sha2-128f",  SLHDSA_SHA2_128F },
    { "sha2-192s",  SLHDSA_SHA2_192S },
    { "sha2-192f",  SLHDSA_SHA2_192F },
    { "sha2-256s",  SLHDSA_SHA2_256S },
    { "sha2-256f",  SLHDSA_SHA2_256F },
#endif
};

static const size_t param_map_sz = sizeof(param_map) / sizeof(param_map[0]);

static void print_usage_and_die(void)
{
    size_t i;

    printf("usage:\n");
    printf("  ./slh_dsa_test [-v] [-s <parameter set>] [-m <message>]\n");
    printf("\n");
    printf("parameter sets:\n");
    for (i = 0; i < param_map_sz; i++)
        printf("  %s\n", param_map[i].name);
    exit(EXIT_FAILURE);
}

static void dump_hex(const char* what, const byte* data, word32 len)
{
    word32 i;

    printf("%s (%u bytes):\n", what, len);
    for (i = 0; i < len; i++) {
        printf("%02x", data[i]);
        if ((i + 1) % 32 == 0)
            printf("\n");
    }
    if (len % 32 != 0)
        printf("\n");
}

int main(int argc, char* argv[])
{
    int              ret;
    int              opt;
    size_t           i;
    const char*      paramName = "shake-128f";
    const char*      msg = "wolfssl slh-dsa example";
    enum SlhDsaParam param = SLHDSA_SHAKE128F;
    int              verbose = 0;
    SlhDsaKey        key;
    int              keyInit = 0;
    WC_RNG           rng;
    int              rngInit = 0;
    byte*            sig = NULL;
    byte             pub[WC_SLHDSA_MAX_PUB_LEN];
    word32           pubLen = (word32)sizeof(pub);
    word32           sigLen = 0;
    int              sigSz;

    while ((opt = getopt(argc, argv, "s:m:v?")) != -1) {
        switch (opt) {
        case 's':
            paramName = optarg;
            break;
        case 'm':
            msg = optarg;
            break;
        case 'v':
            verbose = 1;
            break;
        default:
            print_usage_and_die();
        }
    }

    for (i = 0; i < param_map_sz; i++) {
        if (strcmp(paramName, param_map[i].name) == 0) {
            param = param_map[i].param;
            break;
        }
    }
    if (i == param_map_sz) {
        printf("error: unknown parameter set: %s\n", paramName);
        print_usage_and_die();
    }

    ret = wc_InitRng(&rng);
    if (ret != 0) {
        printf("error: wc_InitRng returned %d\n", ret);
        goto exit;
    }
    rngInit = 1;

    ret = wc_SlhDsaKey_Init(&key, param, NULL, INVALID_DEVID);
    if (ret != 0) {
        printf("error: wc_SlhDsaKey_Init returned %d\n", ret);
        goto exit;
    }
    keyInit = 1;

    sigSz = wc_SlhDsaKey_SigSizeFromParam(param);
    if (sigSz <= 0) {
        ret = sigSz;
        printf("error: wc_SlhDsaKey_SigSizeFromParam returned %d\n", ret);
        goto exit;
    }

    printf("info: using SLH-DSA-%s: pub %d bytes, priv %d bytes, "
           "sig %d bytes\n", paramName,
           wc_SlhDsaKey_PublicSizeFromParam(param),
           wc_SlhDsaKey_PrivateSizeFromParam(param), sigSz);

    sig = malloc((size_t)sigSz);
    if (sig == NULL) {
        ret = MEMORY_E;
        printf("error: malloc(%d) failed\n", sigSz);
        goto exit;
    }
    sigLen = (word32)sigSz;

    printf("info: making key\n");
    ret = wc_SlhDsaKey_MakeKey(&key, &rng);
    if (ret != 0) {
        printf("error: wc_SlhDsaKey_MakeKey returned %d\n", ret);
        goto exit;
    }

    /* ctx=NULL/ctxSz=0 signs with an empty FIPS 205 context string. */
    printf("info: signing message\n");
    ret = wc_SlhDsaKey_Sign(&key, NULL, 0, (const byte*)msg,
                            (word32)strlen(msg), sig, &sigLen, &rng);
    if (ret != 0) {
        printf("error: wc_SlhDsaKey_Sign returned %d\n", ret);
        goto exit;
    }
    if (verbose)
        dump_hex("signature", sig, sigLen);

    ret = wc_SlhDsaKey_ExportPublic(&key, pub, &pubLen);
    if (ret != 0) {
        printf("error: wc_SlhDsaKey_ExportPublic returned %d\n", ret);
        goto exit;
    }
    if (verbose)
        dump_hex("pub key", pub, pubLen);

    /* --- Verify with public key --- */
    {
        SlhDsaKey pubKey;
        ret = wc_SlhDsaKey_Init(&pubKey, param, NULL, INVALID_DEVID);
        if (ret != 0)
            goto exit;
        /* - only have pub key - */
        ret = wc_SlhDsaKey_ImportPublic(&pubKey, pub, pubLen);
        if (ret != 0) {
            printf("error: wc_SlhDsaKey_ImportPublic returned %d\n", ret);
            wc_SlhDsaKey_Free(&pubKey);
            goto exit;
        }
        ret = wc_SlhDsaKey_Verify(&pubKey, NULL, 0, (const byte*)msg,
                                  (word32)strlen(msg), sig, sigLen);
        if (ret != 0) {
            printf("error: wc_SlhDsaKey_Verify returned %d\n", ret);
            wc_SlhDsaKey_Free(&pubKey);
            goto exit;
        }
        printf("info: verify message good\n");

        /* A modified signature must fail verification. */
        sig[0] ^= 0x80;
        ret = wc_SlhDsaKey_Verify(&pubKey, NULL, 0, (const byte*)msg,
                                  (word32)strlen(msg), sig, sigLen);
        if (ret == 0) {
            printf("error: verify of corrupted signature succeeded\n");
            ret = -1;
            wc_SlhDsaKey_Free(&pubKey);
            goto exit;
        }

        wc_SlhDsaKey_Free(&pubKey);
    }
    /* --- Verify with public key --- */

    printf("info: corrupted signature rejected as expected\n");

    ret = 0;
    printf("info: done\n");

exit:
    free(sig);
    if (keyInit)
        wc_SlhDsaKey_Free(&key);
    if (rngInit)
        wc_FreeRng(&rng);

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

#else

int main(void)
{
    printf("Please build wolfSSL with ./configure --enable-slhdsa "
           "(or --enable-slhdsa=yes,sha2 for the SHA2 parameter sets)\n");
    return EXIT_SUCCESS;
}

#endif /* WOLFSSL_HAVE_SLHDSA */
