/* mikey-sakke.c
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

/* Example of the MIKEY-SAKKE identity-based key exchange (RFC 6507-6509):
 * ECCSI signatures plus SAKKE key encapsulation.
 *
 * In identity-based crypto there are no per-user certificates: a user's
 * public key IS their identity (e.g. a phone number or email). A Key
 * Management Service (KMS) holds master secrets and provisions each user's
 * key material out of band.
 *
 * Roles in this example:
 *   KMS:   makes master ECCSI/SAKKE keys, provisions Alice's ECCSI signing
 *          pair (SSK, PVT) and Bob's SAKKE Receiver Secret Key (RSK).
 *   Alice: generates a Shared Secret Value (SSV), encapsulates it to Bob's
 *          identity, and signs the payload with ECCSI (RFC 6509 pattern).
 *   Bob:   verifies Alice's ECCSI signature and derives the SSV with his
 *          RSK. Both then hold the same SSV for use as a session key. */

#include <stdio.h>
#include <string.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/eccsi.h>
#include <wolfssl/wolfcrypt/sakke.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#if defined(WOLFCRYPT_HAVE_ECCSI) && defined(WOLFCRYPT_HAVE_SAKKE)

/* On failure, report and jump to the cleanup label. */
#define CheckError(msg, label) do { \
    if (ret != 0) { \
        printf(msg ": ret %d, line %d\n", ret, __LINE__); \
        goto label; \
    } \
} while (0)

/* Set flag on success */
#define CheckErrorSetFlag(msg, label, flag) do { \
    if (ret != 0) { \
        printf(msg ": ret %d, line %d\n", ret, __LINE__); \
        goto label; \
    } \
    else { \
        flag = 1; \
    } \
} while (0)


/* Sizes below are derived from the parameter sets used by this example:
 * SAKKE 1024-bit (RFC 6509 Appendix A) and ECCSI over NIST P-256.
 * The buffer sizes are compile-time maximums; the authentication size
 * actually used is queried at run time with wc_GetSakkeAuthSize(). */
#define SSV_SZ      16
/* SAKKE 1024-bit: 1 + 2*128 (uncompressed point) */
#define AUTH_SZ     257
/* ECCSI P-256:    32 + 32 + 65  (r || s || PVT) */
#define ECCSI_SIG_SZ 129
/* raw P-256 point:     X || Y */
#define ECCSI_PUB_KEY_SZ  (32 * 2)
/* raw 1024-bit point:  X || Y */
#define SAKKE_PUB_KEY_SZ  (128 * 2)

/* Arbitrary max for simplicity */
#define MAX_ID_SZ   64

static const byte aliceId[] = "alice@example.com";
static const byte bobId[]   = "bob@example.com";

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
        EccsiKey   kmsEccsi;       /* KMS master signing key */
        int        kmsEccsiInit;
        SakkeKey   kmsSakke;       /* KMS master encryption key */
        int        kmsSakkeInit;
    } kms = {0};

    struct {
        byte       kmsAuthPublicKey[ECCSI_PUB_KEY_SZ];   /* KMS ECCSI public key */
        word32     kmsAuthPublicKeySz;
        byte       kmsSakkePublicKey[SAKKE_PUB_KEY_SZ]; /* KMS SAKKE public key */
        word32     kmsSakkePublicKeySz;
    } KmsCertificate = {0};

    struct {
        char       senderId[MAX_ID_SZ];
        byte       payload[SSV_SZ + AUTH_SZ];  /* encapsulated SSV || auth */
        word16     authSz;
        byte       signature[ECCSI_SIG_SZ];
        word32     signatureSz;
    } Message = {0};

    struct {
        EccsiKey   publicKeyEccsi; /* Alice view: KMS public key only */
        int        publicKeyEccsiInit;
        SakkeKey   publicKeySakke; /* Alice view: KMS public key only */
        int        publicKeySakkeInit;
        mp_int     secretSigningKey;
        int        secretSigningKeyInit;
        ecc_point* publicValidationToken;
        ecc_point* receiverSecretKey;
        byte       sharedSecretValue[SSV_SZ]; /* plaintext SSV (Alice's copy) */
        word16     sharedSecretValueSz;
        char*      id;
    } Alice = {0};

    struct {
        EccsiKey   publicKeyEccsi; /* Bobs view: KMS public key only */
        int        publicKeyEccsiInit;
        SakkeKey   publicKeySakke; /* Bob view: KMS public key only */
        int        publicKeySakkeInit;
        mp_int     secretSigningKey;
        int        secretSigningKeyInit;
        ecc_point* publicValidationToken;
        ecc_point* receiverSecretKey;
        byte       derived_sharedSecretValue[SSV_SZ]; /* plaintext SSV (Bob's copy) */
        word16     derived_sharedSecretValueSz;
        char*      id;
    } Bob = {0};

    /* --- Setup KMS --- */
    ret = wc_InitSakkeKey(&kms.kmsSakke, NULL, INVALID_DEVID);
    CheckErrorSetFlag("Could Not Init Sakke Key", exit, kms.kmsSakkeInit);
    ret = wc_InitEccsiKey(&kms.kmsEccsi, NULL, INVALID_DEVID);
    CheckErrorSetFlag("Could Not Init Eccsi Key", exit, kms.kmsEccsiInit);
    /* --- Setup KMS --- */

    /* --- Init Alice --- */
    Alice.id = (char*)aliceId;
    ret = wc_InitEccsiKey(&Alice.publicKeyEccsi, NULL, INVALID_DEVID);
    CheckErrorSetFlag("Could not init Eccsi Key alice", exit,
            Alice.publicKeyEccsiInit);
    ret = wc_InitSakkeKey(&Alice.publicKeySakke, NULL, INVALID_DEVID);
    CheckErrorSetFlag("Could not init Sakke Key alice", exit,
            Alice.publicKeySakkeInit);
    ret = mp_init(&Alice.secretSigningKey);
    CheckErrorSetFlag("Could not init secret signing key alice", exit,
            Alice.secretSigningKeyInit);
    Alice.publicValidationToken = wc_ecc_new_point();
    Alice.receiverSecretKey     = wc_ecc_new_point();
    if (Alice.publicValidationToken == NULL || Alice.receiverSecretKey == NULL){
            ret = MEMORY_E;
            goto exit;
    }
    /* --- Init Alice --- */

    /* --- Init Bob --- */
    Bob.id = (char*)bobId;
    ret = wc_InitEccsiKey(&Bob.publicKeyEccsi, NULL, INVALID_DEVID);
    CheckErrorSetFlag("Could not init Eccsi Key bob", exit,
            Bob.publicKeyEccsiInit);
    ret = wc_InitSakkeKey(&Bob.publicKeySakke, NULL, INVALID_DEVID);
    CheckErrorSetFlag("Could not init Sakke Key bob", exit,
            Bob.publicKeySakkeInit);
    ret = mp_init(&Bob.secretSigningKey);
    CheckErrorSetFlag("Could not init secret signing key bob", exit,
            Bob.secretSigningKeyInit);
    Bob.publicValidationToken = wc_ecc_new_point();
    Bob.receiverSecretKey     = wc_ecc_new_point();
    if (Bob.publicValidationToken == NULL || Bob.receiverSecretKey == NULL) {
        ret = MEMORY_E;
        goto exit;
    }
    /* --- Init Bob --- */



    /* --- One rng instance for simplicity -- */
    ret = wc_InitRng(&rng);
    if (ret != 0) {
        printf("wc_InitRng failed %d\n", ret);
        goto exit;
    }
    rngInit = 1;
    /* --- One rng instance for simplicity -- */


    /* --- KMS setup: master keys --- */
    {
        /* - KMS setup: eccsi keys - */
        ret = wc_MakeEccsiKey(&kms.kmsEccsi, &rng);
        if (ret != 0) {
            printf("wc_MakeEccsiKey failed %d\n", ret);
            goto exit;
        }
        /* - KMS setup: eccsi keys - */

        /* - KMS setup: sakke keys - */
        ret = wc_MakeSakkeKey(&kms.kmsSakke, &rng);
        if (ret != 0) {
            printf("wc_MakeSakkeKey failed %d\n", ret);
            goto exit;
        }
        printf("KMS: master ECCSI and SAKKE keys made\n");
        /* - KMS setup: sakke keys - */
    }
    /* --- KMS setup: master keys --- */


    /* --- Enroll Alice with KMS to get their keys --- */
    {
        /* - Get PublicKeys from KMS (Simulate KMS sending pubkeys only) - */
        KmsCertificate.kmsAuthPublicKeySz = ECCSI_PUB_KEY_SZ;
        ret = wc_ExportEccsiPublicKey(&kms.kmsEccsi,
                KmsCertificate.kmsAuthPublicKey,
                &KmsCertificate.kmsAuthPublicKeySz, 1);
        CheckError("Could not export pub eccsi key from KMS", exit);

        KmsCertificate.kmsSakkePublicKeySz = SAKKE_PUB_KEY_SZ;
        ret = wc_ExportSakkePublicKey(&kms.kmsSakke,
                KmsCertificate.kmsSakkePublicKey,
                &KmsCertificate.kmsSakkePublicKeySz, 1);
        CheckError("Could not export pub Sakke key from KMS", exit);
        /* - Get PublicKeys from KMS (Simulate KMS sending pubkeys only) - */

        /* - Save public key from KMS - */
        ret = wc_ImportEccsiPublicKey(&Alice.publicKeyEccsi,
                    KmsCertificate.kmsAuthPublicKey,
                    KmsCertificate.kmsAuthPublicKeySz, 1);
        if (ret == 0)
            ret = wc_ImportSakkePublicKey(&Alice.publicKeySakke,
                                          KmsCertificate.kmsSakkePublicKey,
                                          KmsCertificate.kmsSakkePublicKeySz, 1);
        CheckError("Unable to transfer kms public keys", exit);
        /* - Save public key from KMS - */

        /* - Get Signing pair from KMS - */
        ret = wc_MakeEccsiPair(&kms.kmsEccsi, &rng, WC_HASH_TYPE_SHA256,
                    (byte*)Alice.id, sizeof(aliceId), &Alice.secretSigningKey,
                    Alice.publicValidationToken);
        CheckError("Unable to make signing pairs", exit);
        /* - Get Signing pair from KMS - */

        /* - Get Issue Receiver Key - */
        ret = wc_MakeSakkeRsk(&kms.kmsSakke, (byte*)Alice.id,
                sizeof(aliceId), Alice.receiverSecretKey);
        CheckError("Unable to make receiver secret key", exit);
        /* - Get Issue Receiver Key - */
    }
    /* --- Enroll Alice with KMS to get their keys --- */

    /* --- Reset Kms Cert for Bob --- */
    memset(&KmsCertificate, 0, sizeof(KmsCertificate));
    /* --- Reset Kms Cert for Bob --- */

    /* --- Enroll Bob with KMS to get their keys --- */
    {
        /* - Get PublicKeys from KMS (Simulate KMS sending pubkeys only) - */
        KmsCertificate.kmsAuthPublicKeySz = ECCSI_PUB_KEY_SZ;
        ret = wc_ExportEccsiPublicKey(&kms.kmsEccsi,
                KmsCertificate.kmsAuthPublicKey,
                &KmsCertificate.kmsAuthPublicKeySz, 1);

        CheckError("Could not export pub eccsi key from KMS", exit);

        KmsCertificate.kmsSakkePublicKeySz = SAKKE_PUB_KEY_SZ;
        ret = wc_ExportSakkePublicKey(&kms.kmsSakke,
                KmsCertificate.kmsSakkePublicKey,
                &KmsCertificate.kmsSakkePublicKeySz, 1);
        CheckError("Could not export pub sakke key from KMS", exit);
        /* - Get PublicKeys from KMS (Simulate KMS sending pubkeys only) - */

        /* - Save public key from KMS - */
        ret = wc_ImportEccsiPublicKey(&Bob.publicKeyEccsi,
                    KmsCertificate.kmsAuthPublicKey,
                    KmsCertificate.kmsAuthPublicKeySz, 1);
        if (ret == 0)
            ret = wc_ImportSakkePublicKey(&Bob.publicKeySakke,
                                          KmsCertificate.kmsSakkePublicKey,
                                          KmsCertificate.kmsSakkePublicKeySz, 1);
        CheckError("Unable to transfer kms public keys", exit);
        /* - Save public key from KMS - */

        /* - Get Signing pair from KMS - */
        ret = wc_MakeEccsiPair(&kms.kmsEccsi, &rng, WC_HASH_TYPE_SHA256,
                    (byte*)Bob.id, sizeof(bobId), &Bob.secretSigningKey,
                    Bob.publicValidationToken);
        CheckError("Unable to make signing pairs", exit);
        /* - Get Signing pair from KMS - */

        /* - Get Issue Receiver Key - */
        ret = wc_MakeSakkeRsk(&kms.kmsSakke, (byte*)Bob.id,
                sizeof(bobId), Bob.receiverSecretKey);
        CheckError("Unable to make receiver secret key", exit);
        /* - Get Issue Receiver Key - */
    }
    /* --- Enroll Bob with KMS to get their keys --- */

    /* --- Alice Creates Message --- */
    {
        byte hashId[WC_MAX_DIGEST_SIZE];
        byte hashIdSz = 0;
        memcpy(Message.senderId, Alice.id, sizeof(aliceId));

        /* - We are handwaving that alice know Bobs Id - */
        ret = wc_SetSakkeIdentity(&Alice.publicKeySakke, (byte*)Bob.id,
                sizeof(bobId));
        CheckError("Could not set Sakke id", exit);
        /* - We are handwaving that alice know Bobs Id - */

        /* - Create SSV - */
        /* Size in is the buffer size wanted; wc_GenerateSakkeSSV rejects 0. */
        Alice.sharedSecretValueSz = SSV_SZ;
        ret = wc_GenerateSakkeSSV(&Alice.publicKeySakke, &rng,
                Alice.sharedSecretValue, &Alice.sharedSecretValueSz);
        CheckError("Could not generate SSV", exit);
        /* - Create SSV - */

        /* - Encapsulate SSV in place - */
        memcpy(Message.payload, Alice.sharedSecretValue,
                Alice.sharedSecretValueSz);
        ret = wc_GetSakkeAuthSize(&Alice.publicKeySakke, &Message.authSz);
        CheckError("Could not get key sz", exit);
        ret = wc_MakeSakkeEncapsulatedSSV(&Alice.publicKeySakke,
                WC_HASH_TYPE_SHA256, Message.payload, Alice.sharedSecretValueSz,
                Message.payload + Alice.sharedSecretValueSz, &Message.authSz);
        CheckError("Could not encapsulate SSV", exit);
        /* - Encapsulate SSV in place - */

        /* - Hash Alices Id - */
        ret = wc_HashEccsiId(&Alice.publicKeyEccsi, WC_HASH_TYPE_SHA256,
                (byte*)Alice.id, sizeof(aliceId), Alice.publicValidationToken,
                hashId, &hashIdSz);
        /* - Hash Alices Id - */

        /* - Load data in to Eccsi Object - */
        if (ret == 0)
            ret = wc_SetEccsiHash(&Alice.publicKeyEccsi, hashId, hashIdSz);
        if (ret == 0)
            ret = wc_SetEccsiPair(&Alice.publicKeyEccsi,
                    &Alice.secretSigningKey, Alice.publicValidationToken);
        /* - Load data in to Eccsi Object - */

        /* - Sign the Eccsi Hash - */
        if (ret == 0) {
            Message.signatureSz = (word32)sizeof(Message.signature);
            ret = wc_SignEccsiHash(&Alice.publicKeyEccsi, &rng,
                    WC_HASH_TYPE_SHA256, Message.payload,
                    Alice.sharedSecretValueSz + Message.authSz,
                    Message.signature, &Message.signatureSz);
        }
        /* - Sign the Eccsi Hash - */

        CheckError("Unable to sign payload", exit);
    }
    /* - Message is ready to send - */
    /* --- Alice Creates Message --- */

    /* --- Bob recives message --- */

    /* --- Bob extracts info from message --- */
    {
        ecc_point* senderPvt;
        byte       hashId[WC_MAX_DIGEST_SIZE];
        byte       hashIdSz = 0;
        int        verified = 0;

        /* Bob signs/derives over the same SSV length Alice used. */
        Bob.derived_sharedSecretValueSz = SSV_SZ;

        senderPvt = wc_ecc_new_point();
        if (senderPvt == NULL) {
            ret = MEMORY_E;
            goto exit;
        }
        /* - Get Sender Public Validation Token - */
        ret = wc_DecodeEccsiPvtFromSig(&Bob.publicKeyEccsi,
                Message.signature, Message.signatureSz, senderPvt);
        CheckError("Could not Decode Pvt.", BobFail);
        /* - Get Sender Public Validation Token - */

        /* - Verify the Message - */
        ret = wc_HashEccsiId(&Bob.publicKeyEccsi, WC_HASH_TYPE_SHA256,
                (byte*)Message.senderId, sizeof(aliceId), senderPvt, hashId,
                &hashIdSz);
        CheckError("Could not Hash Sender Id.", BobFail);
        ret = wc_SetEccsiHash(&Bob.publicKeyEccsi, hashId, hashIdSz);
        CheckError("Could not Set Hash.", BobFail);
        ret = wc_VerifyEccsiHash(&Bob.publicKeyEccsi, WC_HASH_TYPE_SHA256,
                Message.payload,
                Bob.derived_sharedSecretValueSz + Message.authSz,
                Message.signature, Message.signatureSz, &verified);
        /* A bad signature is reported through "verified", not through ret. */
        if (ret == 0 && !verified) ret = SIG_VERIFY_E;
        CheckError("Could not Verify Message.", BobFail);
        /* - Verify the Message - */

        /* - Get The Shared secret value out of the Message - */
        ret = wc_SetSakkeIdentity(&Bob.publicKeySakke, (const byte*)Bob.id,
                sizeof(bobId));
        CheckError("Could not Sakke Id.", BobFail);
        ret = wc_SetSakkeRsk(&Bob.publicKeySakke, Bob.receiverSecretKey,
                NULL, 0);
        CheckError("Could Set Sakke Rsk.", BobFail);
        memcpy(Bob.derived_sharedSecretValue, Message.payload,
                Bob.derived_sharedSecretValueSz);
        ret = wc_DeriveSakkeSSV(&Bob.publicKeySakke, WC_HASH_TYPE_SHA256,
                Bob.derived_sharedSecretValue, Bob.derived_sharedSecretValueSz,
                Message.payload + Bob.derived_sharedSecretValueSz,
                Message.authSz);
        CheckError("Could not derive Sakke SSV.", BobFail);
        /* - Get The Shared secret value out of the Message - */

        /* - Error - */
        if (0) {
BobFail:
            wc_ecc_del_point(senderPvt);
            goto exit;
        }
        wc_ecc_del_point(senderPvt);
    }


    if (memcmp(Alice.sharedSecretValue, Bob.derived_sharedSecretValue,
                SSV_SZ) != 0) {
        printf("SSVs differ!\n");
        ret = -1;
        goto exit;
    }
    print_hex("Shared Secret Value", Alice.sharedSecretValue, SSV_SZ);
    printf("Shared Secret Values match\n");
    ret = 0;

exit:
    if (ret != 0)
        printf("error %d: %s\n", ret, wc_GetErrorString(ret));

    if (Bob.receiverSecretKey != NULL)
        wc_ecc_forcezero_point(Bob.receiverSecretKey);
    wc_ForceZero(Bob.derived_sharedSecretValue,
            sizeof(Bob.derived_sharedSecretValue));
    if (Bob.publicValidationToken != NULL)
        wc_ecc_del_point(Bob.publicValidationToken);
    if (Bob.receiverSecretKey != NULL)
        wc_ecc_del_point(Bob.receiverSecretKey);
    if (Bob.secretSigningKeyInit)
        mp_forcezero(&Bob.secretSigningKey);
    if (Bob.publicKeySakkeInit)
        wc_FreeSakkeKey(&Bob.publicKeySakke);
    if (Bob.publicKeyEccsiInit)
        wc_FreeEccsiKey(&Bob.publicKeyEccsi);

    if (Alice.receiverSecretKey != NULL)
        wc_ecc_forcezero_point(Alice.receiverSecretKey);
    wc_ForceZero(Alice.sharedSecretValue,
            sizeof(Alice.sharedSecretValue));
    if (Alice.publicValidationToken != NULL)
        wc_ecc_del_point(Alice.publicValidationToken);
    if (Alice.receiverSecretKey != NULL)
        wc_ecc_del_point(Alice.receiverSecretKey);
    if (Alice.secretSigningKeyInit)
        mp_forcezero(&Alice.secretSigningKey);
    if (Alice.publicKeySakkeInit)
        wc_FreeSakkeKey(&Alice.publicKeySakke);
    if (Alice.publicKeyEccsiInit)
        wc_FreeEccsiKey(&Alice.publicKeyEccsi);

    if (kms.kmsSakkeInit)
        wc_FreeSakkeKey(&kms.kmsSakke);
    if (kms.kmsEccsiInit)
        wc_FreeEccsiKey(&kms.kmsEccsi);
    if (rngInit)
        wc_FreeRng(&rng);

    return ret == 0 ? 0 : 1;
}

#else

int main(void)
{
    printf("Please build wolfSSL with ./configure --enable-eccsi "
           "--enable-sakke\n");
    return 0;
}

#endif /* WOLFCRYPT_HAVE_ECCSI && WOLFCRYPT_HAVE_SAKKE */
