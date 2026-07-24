/* sm2-sign-verify.c
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

/* Example of SM2 (GB/T 32918) signing and verifying over the SM2 curve.
 *
 * SM2 does not sign the raw message: the message is first combined with the
 * signer's identity and public key into an SM3 digest (the "ZA" hash). */

#include <stdio.h>
#include <string.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/sm2.h>
#include <wolfssl/wolfcrypt/sm3.h>
#include <wolfssl/wolfcrypt/random.h>

#if defined(WOLFSSL_SM2) && defined(WOLFSSL_SM3)

/* Default identity from GM/T 0009-2012, also used for certificates. */
static const byte sm2_id[] = "1234567812345678";

static void print_hex(const char* label, const byte* data, word32 len)
{
    word32 i;

    printf("%s: ", label);
    for (i = 0; i < len; i++)
        printf("%02x", data[i]);
    printf("\n");
}

int main(int argc, char* argv[])
{
    int     ret;
    WC_RNG  rng;
    int     rngInit = 0;
    ecc_key key;
    int     keyInit = 0;
    byte    digest[WC_SM3_DIGEST_SIZE];
    byte    sig[ECC_MAX_SIG_SIZE];
    word32  sigSz = (word32)sizeof(sig);
    int     verified = 0;
    const char* msg = (argc > 1) ? argv[1] : "sm2 sign-verify example";

    ret = wc_InitRng(&rng);
    if (ret != 0) {
        printf("wc_InitRng failed %d\n", ret);
        goto exit;
    }
    rngInit = 1;

    ret = wc_ecc_init(&key);
    if (ret != 0) {
        printf("wc_ecc_init failed %d\n", ret);
        goto exit;
    }
    keyInit = 1;

    ret = wc_ecc_sm2_make_key(&rng, &key, WC_ECC_FLAG_NONE);
    if (ret != 0) {
        printf("wc_ecc_sm2_make_key failed %d\n", ret);
        goto exit;
    }
    printf("Generated SM2 key\n");

    /* ZA digest: SM3 over the identity, curve parameters and public key,
     * then SM3 over ZA || message. */
    ret = wc_ecc_sm2_create_digest(sm2_id, (word16)(sizeof(sm2_id) - 1),
                                   (const byte*)msg, (int)strlen(msg),
                                   WC_HASH_TYPE_SM3, digest,
                                   (int)sizeof(digest), &key);
    if (ret != 0) {
        printf("wc_ecc_sm2_create_digest failed %d\n", ret);
        goto exit;
    }
    print_hex("digest", digest, sizeof(digest));

    ret = wc_ecc_sm2_sign_hash(digest, sizeof(digest), sig, &sigSz, &rng,
                               &key);
    if (ret != 0) {
        printf("wc_ecc_sm2_sign_hash failed %d\n", ret);
        goto exit;
    }
    print_hex("signature", sig, sigSz);

    ret = wc_ecc_sm2_verify_hash(sig, sigSz, digest, sizeof(digest),
                                 &verified, &key);
    if (ret != 0 || verified != 1) {
        printf("wc_ecc_sm2_verify_hash failed: ret %d verified %d\n", ret,
               verified);
        ret = -1;
        goto exit;
    }
    printf("Signature verified\n");

    /* A modified digest must not verify. */
    digest[0] ^= 0x01;
    ret = wc_ecc_sm2_verify_hash(sig, sigSz, digest, sizeof(digest),
                                 &verified, &key);
    if (ret == 0 && verified == 1) {
        printf("Corrupted digest verified!\n");
        ret = -1;
        goto exit;
    }
    printf("Corrupted digest rejected as expected\n");
    ret = 0;

exit:
    if (keyInit)
        wc_ecc_free(&key);
    if (rngInit)
        wc_FreeRng(&rng);

    return ret == 0 ? 0 : 1;
}

#else

int main(void)
{
    printf("Please install the wolfsm overlay and build wolfSSL with "
           "./configure --enable-sm2 --enable-sm3\n");
    return 0;
}

#endif /* WOLFSSL_SM2 && WOLFSSL_SM3 */
