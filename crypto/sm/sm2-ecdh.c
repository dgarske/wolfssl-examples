/* sm2-ecdh.c
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

/* Example of ECDH over the SM2 curve: both sides compute the same shared
 * secret from their private key and the peer's public key.
 *
 * This is plain ECDH on the SM2P256V1 curve, not the full SM2 key exchange
 * protocol from GB/T 32918.3. */

#include <stdio.h>
#include <string.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/sm2.h>
#include <wolfssl/wolfcrypt/random.h>

#ifdef WOLFSSL_SM2

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
    int     ret;
    WC_RNG  rng;
    int     rngInit = 0;
    ecc_key alice;
    ecc_key bob;
    int     aliceInit = 0;
    int     bobInit = 0;
    byte    secretA[32];
    byte    secretB[32];
    word32  secretASz = (word32)sizeof(secretA);
    word32  secretBSz = (word32)sizeof(secretB);

    ret = wc_InitRng(&rng);
    if (ret != 0) {
        printf("wc_InitRng failed %d\n", ret);
        goto exit;
    }
    rngInit = 1;

    ret = wc_ecc_init(&alice);
    if (ret != 0)
        goto exit;
    aliceInit = 1;
    ret = wc_ecc_init(&bob);
    if (ret != 0)
        goto exit;
    bobInit = 1;

    ret = wc_ecc_sm2_make_key(&rng, &alice, WC_ECC_FLAG_NONE);
    if (ret == 0)
        ret = wc_ecc_sm2_make_key(&rng, &bob, WC_ECC_FLAG_NONE);
    if (ret != 0) {
        printf("wc_ecc_sm2_make_key failed %d\n", ret);
        goto exit;
    }
    printf("Generated two SM2 keys\n");

#ifdef ECC_TIMING_RESISTANT
    /* Timing-resistant point math needs an RNG on the private key. */
    ret = wc_ecc_set_rng(&alice, &rng);
    if (ret == 0)
        ret = wc_ecc_set_rng(&bob, &rng);
    if (ret != 0) {
        printf("wc_ecc_set_rng failed %d\n", ret);
        goto exit;
    }
#endif

    /* Each side uses its own private key and the peer's public key. */
    ret = wc_ecc_sm2_shared_secret(&alice, &bob, secretA, &secretASz);
    if (ret == 0)
        ret = wc_ecc_sm2_shared_secret(&bob, &alice, secretB, &secretBSz);
    if (ret != 0) {
        printf("wc_ecc_sm2_shared_secret failed %d\n", ret);
        goto exit;
    }

    print_hex("alice secret", secretA, secretASz);
    print_hex("bob   secret", secretB, secretBSz);

    if (secretASz != secretBSz ||
            memcmp(secretA, secretB, secretASz) != 0) {
        printf("Shared secrets differ!\n");
        ret = -1;
        goto exit;
    }
    printf("Shared secrets match\n");
    ret = 0;

exit:
    if (bobInit)
        wc_ecc_free(&bob);
    if (aliceInit)
        wc_ecc_free(&alice);
    if (rngInit)
        wc_FreeRng(&rng);

    return ret == 0 ? 0 : 1;
}

#else

int main(void)
{
    printf("Please install the wolfsm overlay and build wolfSSL with "
           "./configure --enable-sm2\n");
    return 0;
}

#endif /* WOLFSSL_SM2 */
