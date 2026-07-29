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

/* Example of HPKE (RFC 9180) context reuse: one KEM encapsulation protecting a
 * whole sequence of messages.
 *
 * wc_HpkeSealBase() runs a fresh key encapsulation for every message it
 * protects. With a seal/open context the encapsulation happens once and each
 * message consumes the next AEAD nonce in the sequence, so both sides must
 * process the messages in the same order.
 *
 * Roles in this example:
 *   Receiver: owns the long term HPKE key pair and publishes the public half.
 *             The private half never leaves them.
 *   Sender:   looks up the receiver's public key, makes an ephemeral key pair,
 *             derives a seal context from the two and seals each message.
 *
 * Everything that crosses the wire lives in the Message struct: the serialized
 * ephemeral public key (the KEM encapsulation) plus the ciphertexts. */

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
#define TAG_SZ   16                   /* AES-GCM authentication tag */
#define MAX_MSG  64

static const char* msgs[NUM_MSGS] = {
    "first message",
    "second message",
    "third message"
};

static const char* info = "hpke context example";
static const char* aad  = "message aad";

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

    int        ret;
    int        i;

    WC_RNG     rng;
    int        rngInit = 0;

    /* Every struct below is declared before the first "goto exit" so that the
     * cleanup at the bottom always sees initialised members. */
    struct {
        Hpke            suite;          /* KEM/KDF/AEAD ids, agreed in advance */
        void*           staticKey;      /* long term pair, private half kept */
        HpkeBaseContext openCtx;
        byte            plain[MAX_MSG];
    } Receiver = {0};

    struct {
        Hpke            suite;          /* same suite, separate instance */
        void*           receiverKey;    /* Sender view: public key only */
        void*           ephemeralKey;   /* fresh per conversation */
        HpkeBaseContext sealCtx;
    } Sender = {0};

    struct {
        byte       receiverPubKey[HPKE_Npk_MAX];  /* what Receiver publishes */
        word16     receiverPubKeySz;
    } Directory = {0};

    struct {
        byte       ephemeralPubKey[HPKE_Npk_MAX]; /* the KEM encapsulation */
        word16     ephemeralPubKeySz;
        byte       cipher[NUM_MSGS][MAX_MSG + TAG_SZ];
        word32     cipherSz[NUM_MSGS];  /* body length; the tag follows it */
    } Message = {0};

    /* --- Setup Receiver --- */
    /* Curve25519 when available, otherwise P-256. Both sides must pick the
     * same triple or the key schedule will not line up. */
#if defined(HAVE_CURVE25519)
    ret = wc_HpkeInit(&Receiver.suite, DHKEM_X25519_HKDF_SHA256, HKDF_SHA256,
            HPKE_AES_128_GCM, NULL);
#else
    ret = wc_HpkeInit(&Receiver.suite, DHKEM_P256_HKDF_SHA256, HKDF_SHA256,
            HPKE_AES_128_GCM, NULL);
#endif
    if (ret != 0) {printf("Receiver could not init HPKE suite\n"); goto exit;}
    /* --- Setup Receiver --- */

    /* --- Setup Sender --- */
#if defined(HAVE_CURVE25519)
    ret = wc_HpkeInit(&Sender.suite, DHKEM_X25519_HKDF_SHA256, HKDF_SHA256,
            HPKE_AES_128_GCM, NULL);
#else
    ret = wc_HpkeInit(&Sender.suite, DHKEM_P256_HKDF_SHA256, HKDF_SHA256,
            HPKE_AES_128_GCM, NULL);
#endif
    if (ret != 0) {printf("Sender could not init HPKE suite\n"); goto exit;}
    /* --- Setup Sender --- */

    /* --- One rng instance for simplicity -- */
    ret = wc_InitRng(&rng);
    if (ret != 0) {
        printf("wc_InitRng failed %d\n", ret);
        goto exit;
    }
    rngInit = 1;
    /* --- One rng instance for simplicity -- */

    /* --- Receiver publishes a static public key --- */
    {
        /* - Make the long term pair - */
        ret = wc_HpkeGenerateKeyPair(&Receiver.suite, &Receiver.staticKey,
                &rng);
        if (ret != 0) {printf("Receiver could not make key pair\n"); goto exit;}
        /* - Make the long term pair - */

        /* - Publish the public half (Simulate a key directory) - */
        Directory.receiverPubKeySz = (word16)sizeof(Directory.receiverPubKey);
        ret = wc_HpkeSerializePublicKey(&Receiver.suite, Receiver.staticKey,
                Directory.receiverPubKey, &Directory.receiverPubKeySz);
        if (ret != 0) {printf("Could not serialize receiver key\n"); goto exit;}
        printf("Receiver: static HPKE key pair made and published\n");
        /* - Publish the public half (Simulate a key directory) - */
    }
    /* --- Receiver publishes a static public key --- */

    /* --- Sender looks up the Receiver and makes an ephemeral key --- */
    {
        /* - Sender only ever holds the public key - */
        ret = wc_HpkeDeserializePublicKey(&Sender.suite, &Sender.receiverKey,
                Directory.receiverPubKey, Directory.receiverPubKeySz);
        if (ret != 0) {printf("Could not import receiver key\n"); goto exit;}
        /* - Sender only ever holds the public key - */

        /* - Fresh ephemeral pair, one per conversation - */
        ret = wc_HpkeGenerateKeyPair(&Sender.suite, &Sender.ephemeralKey, &rng);
        if (ret != 0) {
            printf("Sender could not make ephemeral key\n");
            goto exit;
        }
        /* - Fresh ephemeral pair, one per conversation - */
    }
    /* --- Sender looks up the Receiver and makes an ephemeral key --- */

    /* --- Sender Creates Messages --- */
    {
        /* - Encapsulate once; the context carries the nonce sequence - */
        ret = wc_HpkeInitSealContext(&Sender.suite, &Sender.sealCtx,
                Sender.ephemeralKey, Sender.receiverKey, (byte*)info,
                (word32)strlen(info));
        if (ret != 0) {printf("Could not init seal context\n"); goto exit;}
        /* - Encapsulate once; the context carries the nonce sequence - */

        /* - Seal each message in order - */
        for (i = 0; i < NUM_MSGS; i++) {
            Message.cipherSz[i] = (word32)strlen(msgs[i]);
            if (Message.cipherSz[i] > MAX_MSG) {
                printf("message %d too long for buffer\n", i);
                ret = BUFFER_E;
                goto exit;
            }
            ret = wc_HpkeContextSealBase(&Sender.suite, &Sender.sealCtx,
                    (byte*)aad, (word32)strlen(aad), (byte*)msgs[i],
                    Message.cipherSz[i], Message.cipher[i]);
            if (ret != 0) {printf("Could not seal message %d\n", i); goto exit;}
            printf("sealed message %d (%u bytes)\n", i,
                    (unsigned int)Message.cipherSz[i]);
        }
        /* - Seal each message in order - */

        /* - Only the ephemeral public key travels alongside the ciphertexts - */
        Message.ephemeralPubKeySz = (word16)sizeof(Message.ephemeralPubKey);
        ret = wc_HpkeSerializePublicKey(&Sender.suite, Sender.ephemeralKey,
                Message.ephemeralPubKey, &Message.ephemeralPubKeySz);
        if (ret != 0) {printf("Could not serialize ephemeral key\n"); goto exit;}
        print_hex("KEM encapsulation", Message.ephemeralPubKey,
                Message.ephemeralPubKeySz);
        /* - Only the ephemeral public key travels alongside the ciphertexts - */

        /* - Messages are ready to send - */
    }
    /* --- Sender Creates Messages --- */

    /* --- Receiver opens the messages --- */
    {
        /* - Decapsulate once with the private half - */
        ret = wc_HpkeInitOpenContext(&Receiver.suite, &Receiver.openCtx,
                Receiver.staticKey, Message.ephemeralPubKey,
                Message.ephemeralPubKeySz, (byte*)info, (word32)strlen(info));
        if (ret != 0) {printf("Could not init open context\n"); goto exit;}
        /* - Decapsulate once with the private half - */

        /* - Open in the same order the Sender sealed - */
        for (i = 0; i < NUM_MSGS; i++) {
            memset(Receiver.plain, 0, sizeof(Receiver.plain));
            ret = wc_HpkeContextOpenBase(&Receiver.suite, &Receiver.openCtx,
                    (byte*)aad, (word32)strlen(aad), Message.cipher[i],
                    Message.cipherSz[i], Receiver.plain);
            if (ret != 0) {printf("Could not open message %d\n", i); goto exit;}

            if (memcmp(Receiver.plain, msgs[i], Message.cipherSz[i]) != 0) {
                printf("message %d mismatch\n", i);
                ret = -1;
                goto exit;
            }
            printf("opened message %d: %.*s\n", i, (int)Message.cipherSz[i],
                    Receiver.plain);
        }
        /* - Open in the same order the Sender sealed - */
    }
    /* --- Receiver opens the messages --- */

    /* --- A replay lands on the wrong nonce and is rejected --- */
    ret = wc_HpkeContextOpenBase(&Receiver.suite, &Receiver.openCtx,
            (byte*)aad, (word32)strlen(aad), Message.cipher[0],
            Message.cipherSz[0], Receiver.plain);
    if (ret == 0) {
        printf("out-of-order open succeeded unexpectedly\n");
        ret = -1;
        goto exit;
    }
    printf("out-of-order open rejected as expected\n");
    ret = 0;
    /* --- A replay lands on the wrong nonce and is rejected --- */

    printf("HPKE context test success\n");

exit:
    if (ret != 0)
        printf("HPKE context test error %d: %s\n", ret,
               wc_GetErrorString(ret));

    if (Sender.ephemeralKey != NULL)
        wc_HpkeFreeKey(&Sender.suite, Sender.suite.kem, Sender.ephemeralKey,
                NULL);
    if (Sender.receiverKey != NULL)
        wc_HpkeFreeKey(&Sender.suite, Sender.suite.kem, Sender.receiverKey,
                NULL);

    if (Receiver.staticKey != NULL)
        wc_HpkeFreeKey(&Receiver.suite, Receiver.suite.kem, Receiver.staticKey,
                NULL);

    if (rngInit)
        wc_FreeRng(&rng);

    return ret == 0 ? 0 : 1;
}

#else

int main(void)
{
    printf("Please build wolfssl with ./configure --enable-hpke "
           "--enable-aesgcm --enable-curve25519 --enable-ecc\n");
    return 0;
}

#endif /* HAVE_HPKE && (HAVE_ECC || HAVE_CURVE25519) && HAVE_AESGCM */
