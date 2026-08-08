/* sm4-gcm-encrypt.c
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

/* Example of SM4-GCM (GB/T 32907-2016 block cipher in GCM mode) authenticated
 * encryption: encrypt, decrypt, and reject a tampered tag. */

#include <stdio.h>
#include <string.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/sm4.h>
#include <wolfssl/wolfcrypt/random.h>

#if defined(WOLFSSL_SM4) && defined(WOLFSSL_SM4_GCM)

#define NONCE_SZ 12
#define TAG_SZ   16

static void print_hex(const char* label, const byte* data, word32 len)
{
    word32 i;

    printf("%s: ", label);
    for (i = 0; i < len; i++)
        printf("%02x", data[i]);
    printf("\n");
}

int main(void)
{
    int    ret;
    wc_Sm4 sm4;
    int    sm4Init = 0;
    WC_RNG rng;
    int    rngInit = 0;
    byte   key[SM4_KEY_SIZE];
    byte   nonce[NONCE_SZ];
    byte   tag[TAG_SZ];
    const char* msg = "sm4-gcm example plaintext";
    const char* aad = "example aad";
    byte   cipher[64];
    byte   plain[64];
    word32 msgSz = (word32)strlen(msg);

    ret = wc_InitRng(&rng);
    if (ret != 0) {
        printf("wc_InitRng failed %d\n", ret);
        goto exit;
    }
    rngInit = 1;

    ret = wc_Sm4Init(&sm4, NULL, INVALID_DEVID);
    if (ret != 0) {
        printf("wc_Sm4Init failed %d\n", ret);
        goto exit;
    }
    sm4Init = 1;

    /* Fresh random key; a nonce must never repeat under the same key. */
    ret = wc_RNG_GenerateBlock(&rng, key, sizeof(key));
    if (ret == 0)
        ret = wc_RNG_GenerateBlock(&rng, nonce, sizeof(nonce));
    if (ret != 0) {
        printf("wc_RNG_GenerateBlock failed %d\n", ret);
        goto exit;
    }

    ret = wc_Sm4GcmSetKey(&sm4, key, sizeof(key));
    if (ret != 0) {
        printf("wc_Sm4GcmSetKey failed %d\n", ret);
        goto exit;
    }

    ret = wc_Sm4GcmEncrypt(&sm4, cipher, (const byte*)msg, msgSz, nonce,
                           sizeof(nonce), tag, sizeof(tag), (const byte*)aad,
                           (word32)strlen(aad));
    if (ret != 0) {
        printf("wc_Sm4GcmEncrypt failed %d\n", ret);
        goto exit;
    }
    print_hex("key       ", key, sizeof(key));
    print_hex("nonce     ", nonce, sizeof(nonce));
    print_hex("ciphertext", cipher, msgSz);
    print_hex("tag       ", tag, sizeof(tag));

    ret = wc_Sm4GcmDecrypt(&sm4, plain, cipher, msgSz, nonce, sizeof(nonce),
                           tag, sizeof(tag), (const byte*)aad,
                           (word32)strlen(aad));
    if (ret != 0) {
        printf("wc_Sm4GcmDecrypt failed %d\n", ret);
        goto exit;
    }
    if (memcmp(plain, msg, msgSz) != 0) {
        printf("Decrypted plaintext mismatch!\n");
        ret = -1;
        goto exit;
    }
    printf("Decrypt success\n");

    /* A tampered tag must fail authentication. */
    tag[0] ^= 0x01;
    ret = wc_Sm4GcmDecrypt(&sm4, plain, cipher, msgSz, nonce, sizeof(nonce),
                           tag, sizeof(tag), (const byte*)aad,
                           (word32)strlen(aad));
    if (ret == 0) {
        printf("Tampered tag accepted!\n");
        ret = -1;
        goto exit;
    }
    printf("Tampered tag rejected as expected\n");
    ret = 0;

exit:
    if (sm4Init)
        wc_Sm4Free(&sm4);
    if (rngInit)
        wc_FreeRng(&rng);

    return ret == 0 ? 0 : 1;
}

#else

int main(void)
{
    printf("Please install the wolfsm overlay and build wolfSSL with "
           "./configure --enable-sm4-gcm\n");
    return 0;
}

#endif /* WOLFSSL_SM4 && WOLFSSL_SM4_GCM */
