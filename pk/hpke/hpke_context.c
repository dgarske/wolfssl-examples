/* hpke_context.c
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

/* Example of HPKE (RFC 9180) context reuse: one KEM encapsulation protecting
 * a sequence of messages.
 *
 * wc_HpkeSealBase() does a fresh key encapsulation per message. With a
 * seal/open context the encapsulation happens once and each message gets the
 * next AEAD nonce, so both sides must process messages in the same order. */

#include <stdio.h>
#include <string.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/hpke.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#if defined(HAVE_HPKE) && (defined(HAVE_ECC) || defined(HAVE_CURVE25519)) && \
    defined(HAVE_AESGCM)

#define NUM_MSGS 3
#define TAG_SZ   16
#define MAX_MSG  64

static const char* msgs[NUM_MSGS] = {
    "first message",
    "second message",
    "third message"
};

int main(void)
{
    int             ret;
    int             i;
    Hpke            hpke[1];
    HpkeBaseContext sealCtx[1];
    HpkeBaseContext openCtx[1];
    WC_RNG          rng[1];
    int             rngInit = 0;
    void*           receiverKey = NULL;
    void*           ephemeralKey = NULL;
    byte            pubKey[HPKE_Npk_MAX];
    word16          pubKeySz = (word16)sizeof(pubKey);
    byte            cipher[NUM_MSGS][MAX_MSG + TAG_SZ];
    byte            plain[MAX_MSG];
    const char*     info = "hpke context example";
    const char*     aad = "message aad";

#if defined(HAVE_CURVE25519)
    ret = wc_HpkeInit(hpke, DHKEM_X25519_HKDF_SHA256, HKDF_SHA256,
                      HPKE_AES_128_GCM, NULL);
#else
    ret = wc_HpkeInit(hpke, DHKEM_P256_HKDF_SHA256, HKDF_SHA256,
                      HPKE_AES_128_GCM, NULL);
#endif
    if (ret != 0)
        goto exit;

    ret = wc_InitRng(rng);
    if (ret != 0)
        goto exit;
    rngInit = 1;

    ret = wc_HpkeGenerateKeyPair(hpke, &receiverKey, rng);
    if (ret == 0)
        ret = wc_HpkeGenerateKeyPair(hpke, &ephemeralKey, rng);
    if (ret != 0)
        goto exit;

    /* Sender: one encapsulation, then seal each message in order. */
    ret = wc_HpkeInitSealContext(hpke, sealCtx, ephemeralKey, receiverKey,
                                 (byte*)info, (word32)strlen(info));
    if (ret != 0)
        goto exit;

    for (i = 0; i < NUM_MSGS; i++) {
        ret = wc_HpkeContextSealBase(hpke, sealCtx, (byte*)aad,
                                     (word32)strlen(aad), (byte*)msgs[i],
                                     (word32)strlen(msgs[i]), cipher[i]);
        if (ret != 0)
            goto exit;
        printf("sealed message %d (%zu bytes)\n", i, strlen(msgs[i]));
    }

    /* Only the ephemeral public key travels to the receiver. */
    ret = wc_HpkeSerializePublicKey(hpke, ephemeralKey, pubKey, &pubKeySz);
    if (ret != 0)
        goto exit;

    /* Receiver: decapsulate once, then open in the same order. */
    ret = wc_HpkeInitOpenContext(hpke, openCtx, receiverKey, pubKey, pubKeySz,
                                 (byte*)info, (word32)strlen(info));
    if (ret != 0)
        goto exit;

    for (i = 0; i < NUM_MSGS; i++) {
        word32 msgSz = (word32)strlen(msgs[i]);

        memset(plain, 0, sizeof(plain));
        ret = wc_HpkeContextOpenBase(hpke, openCtx, (byte*)aad,
                                     (word32)strlen(aad), cipher[i], msgSz,
                                     plain);
        if (ret != 0)
            goto exit;
        if (memcmp(plain, msgs[i], msgSz) != 0) {
            printf("message %d mismatch\n", i);
            ret = -1;
            goto exit;
        }
        printf("opened message %d: %.*s\n", i, (int)msgSz, plain);
    }

    /* Replaying a message out of sequence uses the wrong nonce and fails. */
    ret = wc_HpkeContextOpenBase(hpke, openCtx, (byte*)aad,
                                 (word32)strlen(aad), cipher[0],
                                 (word32)strlen(msgs[0]), plain);
    if (ret == 0) {
        printf("out-of-order open succeeded unexpectedly\n");
        ret = -1;
        goto exit;
    }
    printf("out-of-order open rejected as expected\n");
    ret = 0;

    printf("HPKE context test success\n");

exit:
    if (ret != 0)
        printf("HPKE context test error %d: %s\n", ret,
               wc_GetErrorString(ret));
    if (ephemeralKey != NULL)
        wc_HpkeFreeKey(hpke, hpke->kem, ephemeralKey, NULL);
    if (receiverKey != NULL)
        wc_HpkeFreeKey(hpke, hpke->kem, receiverKey, NULL);
    if (rngInit)
        wc_FreeRng(rng);

    return ret == 0 ? 0 : 1;
}

#else

int main(void)
{
    printf("Please build wolfssl with ./configure --enable-hpke "
           "--enable-aesgcm --enable-curve25519 --enable-ecc\n");
    return 0;
}

#endif
