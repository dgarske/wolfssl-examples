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
 * protocol from GB/T 32918.3.
 *
 * Roles in this example:
 *   Alice: makes an SM2 key pair, sends her public key to Bob, and combines
 *          her private key with Bob's public key.
 *   Bob:   does the same in the other direction.
 *
 * Only public keys are exchanged, so each side is given its own ecc_key for
 * the peer, imported from the bytes that crossed the wire. Both then arrive
 * at the same secret without it ever being transmitted. */

#include <stdio.h>
#include <string.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/sm2.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#ifdef WOLFSSL_SM2

#define SM2_FIELD_SZ    32                       /* SM2P256V1: 256-bit curve */
#define SM2_SECRET_SZ   SM2_FIELD_SZ             /* ECDH secret is one X ord */
#define SM2_PUB_KEY_SZ  (1 + SM2_FIELD_SZ * 2)   /* X9.63 point: 04 || X || Y */

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

    WC_RNG     rng;
    int        rngInit = 0;

    /* Every struct below is declared before the first "goto exit" so that the
     * cleanup at the bottom always sees initialised members. */
    struct {
        byte       publicKey[SM2_PUB_KEY_SZ];  /* only public data is sent */
        word32     publicKeySz;
    } Wire = {0};

    struct {
        ecc_key    key;                        /* Alice's own key pair */
        int        keyInit;
        ecc_key    peerKey;                    /* Alice view: Bob's pubkey */
        int        peerKeyInit;
        byte       sharedSecret[SM2_SECRET_SZ];
        word32     sharedSecretSz;
    } Alice = {0};

    struct {
        ecc_key    key;                        /* Bob's own key pair */
        int        keyInit;
        ecc_key    peerKey;                    /* Bob view: Alice's pubkey */
        int        peerKeyInit;
        byte       sharedSecret[SM2_SECRET_SZ];
        word32     sharedSecretSz;
    } Bob = {0};

    /* --- Init Alice --- */
    ret = wc_ecc_init(&Alice.key);
    if (ret != 0) goto exit; else Alice.keyInit = 1;
    ret = wc_ecc_init(&Alice.peerKey);
    if (ret != 0) goto exit; else Alice.peerKeyInit = 1;
    Alice.sharedSecretSz = (word32)sizeof(Alice.sharedSecret);
    /* --- Init Alice --- */

    /* --- Init Bob --- */
    ret = wc_ecc_init(&Bob.key);
    if (ret != 0) goto exit; else Bob.keyInit = 1;
    ret = wc_ecc_init(&Bob.peerKey);
    if (ret != 0) goto exit; else Bob.peerKeyInit = 1;
    Bob.sharedSecretSz = (word32)sizeof(Bob.sharedSecret);
    /* --- Init Bob --- */

    /* --- One rng instance for simplicity -- */
    ret = wc_InitRng(&rng);
    if (ret != 0) {
        printf("wc_InitRng failed %d\n", ret);
        goto exit;
    }
    rngInit = 1;
    /* --- One rng instance for simplicity -- */

    /* --- Each side makes its own SM2 key pair --- */
    ret = wc_ecc_sm2_make_key(&rng, &Alice.key, WC_ECC_FLAG_NONE);
    if (ret == 0)
        ret = wc_ecc_sm2_make_key(&rng, &Bob.key, WC_ECC_FLAG_NONE);
    if (ret != 0) {
        printf("wc_ecc_sm2_make_key failed %d\n", ret);
        goto exit;
    }
    printf("Generated two SM2 keys\n");
    /* --- Each side makes its own SM2 key pair --- */

#ifdef ECC_TIMING_RESISTANT
    /* --- Timing-resistant point math needs an RNG on the private key --- */
    ret = wc_ecc_set_rng(&Alice.key, &rng);
    if (ret == 0)
        ret = wc_ecc_set_rng(&Bob.key, &rng);
    if (ret != 0) {
        printf("wc_ecc_set_rng failed %d\n", ret);
        goto exit;
    }
    /* --- Timing-resistant point math needs an RNG on the private key --- */
#endif

    /* --- Alice sends her public key to Bob --- */
    {
        /* - Export Alice's public point (simulate sending pubkey only) - */
        Wire.publicKeySz = SM2_PUB_KEY_SZ;
        ret = wc_ecc_export_x963_ex(&Alice.key, Wire.publicKey,
                &Wire.publicKeySz, 0);
        if (ret != 0) {printf("Could not export Alice's pubkey\n"); goto exit;}
        /* - Export Alice's public point (simulate sending pubkey only) - */

        /* - Bob saves the public key he received - */
        ret = wc_ecc_import_x963_ex(Wire.publicKey, Wire.publicKeySz,
                &Bob.peerKey, ECC_SM2P256V1);
        if (ret != 0) {
            printf("Bob could not import Alice's pubkey\n");
            goto exit;
        }
        /* - Bob saves the public key he received - */
    }
    /* --- Alice sends her public key to Bob --- */

    /* --- Reset the wire for Bob's public key --- */
    memset(&Wire, 0, sizeof(Wire));
    /* --- Reset the wire for Bob's public key --- */

    /* --- Bob sends his public key to Alice --- */
    {
        /* - Export Bob's public point (simulate sending pubkey only) - */
        Wire.publicKeySz = SM2_PUB_KEY_SZ;
        ret = wc_ecc_export_x963_ex(&Bob.key, Wire.publicKey,
                &Wire.publicKeySz, 0);
        if (ret != 0) {printf("Could not export Bob's pubkey\n"); goto exit;}
        /* - Export Bob's public point (simulate sending pubkey only) - */

        /* - Alice saves the public key she received - */
        ret = wc_ecc_import_x963_ex(Wire.publicKey, Wire.publicKeySz,
                &Alice.peerKey, ECC_SM2P256V1);
        if (ret != 0) {
            printf("Alice could not import Bob's pubkey\n");
            goto exit;
        }
        /* - Alice saves the public key she received - */
    }
    /* --- Bob sends his public key to Alice --- */

    /* --- Each side computes the shared secret --- */
    /* Own private key plus the peer's public key. The size in is the buffer
     * size available; on return it holds the secret length. */
    ret = wc_ecc_sm2_shared_secret(&Alice.key, &Alice.peerKey,
            Alice.sharedSecret, &Alice.sharedSecretSz);
    if (ret == 0)
        ret = wc_ecc_sm2_shared_secret(&Bob.key, &Bob.peerKey,
                Bob.sharedSecret, &Bob.sharedSecretSz);
    if (ret != 0) {
        printf("wc_ecc_sm2_shared_secret failed %d\n", ret);
        goto exit;
    }
    /* --- Each side computes the shared secret --- */

    print_hex("alice secret", Alice.sharedSecret, Alice.sharedSecretSz);
    print_hex("bob   secret", Bob.sharedSecret, Bob.sharedSecretSz);

    if (Alice.sharedSecretSz != Bob.sharedSecretSz ||
            memcmp(Alice.sharedSecret, Bob.sharedSecret,
                   Alice.sharedSecretSz) != 0) {
        printf("Shared secrets differ!\n");
        ret = -1;
        goto exit;
    }
    printf("Shared secrets match\n");
    ret = 0;

exit:
    if (ret != 0)
        printf("error %d: %s\n", ret, wc_GetErrorString(ret));

    if (Bob.peerKeyInit)
        wc_ecc_free(&Bob.peerKey);
    if (Bob.keyInit)
        wc_ecc_free(&Bob.key);

    if (Alice.peerKeyInit)
        wc_ecc_free(&Alice.peerKey);
    if (Alice.keyInit)
        wc_ecc_free(&Alice.key);

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
