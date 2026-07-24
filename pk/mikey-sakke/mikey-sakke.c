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

#define SSV_SZ      16
#define AUTH_SZ     257
#define ECCSI_SIG_SZ 129
#define PUB_KEY_SZ  (32 * 2)

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
    EccsiKey   kmsEccsi;       /* KMS master signing key */
    EccsiKey   userEccsi;      /* Alice/Bob view: KMS public key only */
    int        kmsEccsiInit = 0;
    int        userEccsiInit = 0;
    SakkeKey   kmsSakke;       /* KMS master encryption key */
    SakkeKey   userSakke;      /* Alice/Bob view: KMS public key only */
    int        kmsSakkeInit = 0;
    int        userSakkeInit = 0;
    mp_int     ssk;
    int        sskInit = 0;
    ecc_point* pvt = NULL;
    ecc_point* rsk = NULL;
    byte       kpak[PUB_KEY_SZ];       /* KMS ECCSI public key */
    word32     kpakSz = (word32)sizeof(kpak);
    byte       zpub[PUB_KEY_SZ * 4 + 1]; /* KMS SAKKE public key */
    word32     zpubSz = (word32)sizeof(zpub);
    byte       hashId[WC_MAX_DIGEST_SIZE];
    byte       hashIdSz = 0;
    byte       ssv[SSV_SZ];            /* plaintext SSV (Alice's copy) */
    word16     ssvSz = SSV_SZ;
    byte       payload[SSV_SZ + AUTH_SZ]; /* encapsulated SSV || auth */
    word16     authSz = 0;
    byte       sig[ECCSI_SIG_SZ];
    word32     sigSz = (word32)sizeof(sig);
    int        verified = 0;

    ret = wc_InitRng(&rng);
    if (ret != 0) {
        printf("wc_InitRng failed %d\n", ret);
        goto exit;
    }
    rngInit = 1;

    /* --- KMS setup: master keys and per-user provisioning. --- */
    ret = wc_InitEccsiKey(&kmsEccsi, NULL, INVALID_DEVID);
    if (ret != 0)
        goto exit;
    kmsEccsiInit = 1;
    ret = wc_MakeEccsiKey(&kmsEccsi, &rng);
    if (ret != 0) {
        printf("wc_MakeEccsiKey failed %d\n", ret);
        goto exit;
    }

    ret = wc_InitSakkeKey(&kmsSakke, NULL, INVALID_DEVID);
    if (ret != 0)
        goto exit;
    kmsSakkeInit = 1;
    ret = wc_MakeSakkeKey(&kmsSakke, &rng);
    if (ret != 0) {
        printf("wc_MakeSakkeKey failed %d\n", ret);
        goto exit;
    }
    printf("KMS: master ECCSI and SAKKE keys made\n");

    /* Alice's ECCSI signing pair for her identity. */
    ret = mp_init(&ssk);
    if (ret != 0)
        goto exit;
    sskInit = 1;
    pvt = wc_ecc_new_point();
    rsk = wc_ecc_new_point();
    if (pvt == NULL || rsk == NULL) {
        ret = MEMORY_E;
        goto exit;
    }
    ret = wc_MakeEccsiPair(&kmsEccsi, &rng, WC_HASH_TYPE_SHA256, aliceId,
                           (word32)sizeof(aliceId) - 1, &ssk, pvt);
    if (ret != 0) {
        printf("wc_MakeEccsiPair failed %d\n", ret);
        goto exit;
    }
    printf("KMS: provisioned ECCSI pair for '%s'\n", (const char*)aliceId);

    /* Bob's SAKKE RSK for his identity. */
    ret = wc_MakeSakkeRsk(&kmsSakke, bobId, (word16)sizeof(bobId) - 1, rsk);
    if (ret != 0) {
        printf("wc_MakeSakkeRsk failed %d\n", ret);
        goto exit;
    }
    printf("KMS: provisioned SAKKE RSK for '%s'\n", (const char*)bobId);

    /* Users get only the KMS public keys. */
    ret = wc_ExportEccsiPublicKey(&kmsEccsi, kpak, &kpakSz, 1);
    if (ret == 0)
        ret = wc_ExportSakkePublicKey(&kmsSakke, zpub, &zpubSz, 1);
    if (ret != 0) {
        printf("KMS public key export failed %d\n", ret);
        goto exit;
    }

    ret = wc_InitEccsiKey(&userEccsi, NULL, INVALID_DEVID);
    if (ret != 0)
        goto exit;
    userEccsiInit = 1;
    ret = wc_ImportEccsiPublicKey(&userEccsi, kpak, kpakSz, 1);
    if (ret != 0) {
        printf("wc_ImportEccsiPublicKey failed %d\n", ret);
        goto exit;
    }

    ret = wc_InitSakkeKey(&userSakke, NULL, INVALID_DEVID);
    if (ret != 0)
        goto exit;
    userSakkeInit = 1;
    ret = wc_ImportSakkePublicKey(&userSakke, zpub, zpubSz, 1);
    if (ret != 0) {
        printf("wc_ImportSakkePublicKey failed %d\n", ret);
        goto exit;
    }

    /* --- Alice: encapsulate a fresh SSV to Bob's identity. --- */
    ret = wc_SetSakkeIdentity(&userSakke, bobId, (word16)sizeof(bobId) - 1);
    if (ret != 0)
        goto exit;
    authSz = AUTH_SZ;
    ret = wc_GenerateSakkeSSV(&userSakke, &rng, ssv, &ssvSz);
    if (ret != 0) {
        printf("wc_GenerateSakkeSSV failed %d\n", ret);
        goto exit;
    }
    print_hex("Alice: SSV", ssv, SSV_SZ);

    /* Encapsulation masks the SSV in place; keep Alice's plaintext copy. */
    memcpy(payload, ssv, SSV_SZ);
    ret = wc_MakeSakkeEncapsulatedSSV(&userSakke, WC_HASH_TYPE_SHA256,
                                      payload, SSV_SZ, payload + SSV_SZ,
                                      &authSz);
    if (ret != 0) {
        printf("wc_MakeSakkeEncapsulatedSSV failed %d\n", ret);
        goto exit;
    }
    printf("Alice: SSV encapsulated to '%s' (%u byte auth)\n",
           (const char*)bobId, authSz);

    /* Alice signs the whole payload with her identity's ECCSI pair. */
    ret = wc_HashEccsiId(&userEccsi, WC_HASH_TYPE_SHA256, aliceId,
                         (word32)sizeof(aliceId) - 1, pvt, hashId, &hashIdSz);
    if (ret == 0)
        ret = wc_SetEccsiHash(&userEccsi, hashId, hashIdSz);
    if (ret == 0)
        ret = wc_SetEccsiPair(&userEccsi, &ssk, pvt);
    if (ret == 0)
        ret = wc_SignEccsiHash(&userEccsi, &rng, WC_HASH_TYPE_SHA256,
                               payload, SSV_SZ + authSz, sig, &sigSz);
    if (ret != 0) {
        printf("ECCSI signing failed %d\n", ret);
        goto exit;
    }
    printf("Alice: payload signed with ECCSI (%u byte signature)\n", sigSz);

    /* --- Bob: verify Alice's signature, then derive the SSV. --- */
    ret = wc_HashEccsiId(&userEccsi, WC_HASH_TYPE_SHA256, aliceId,
                         (word32)sizeof(aliceId) - 1, pvt, hashId, &hashIdSz);
    if (ret == 0)
        ret = wc_SetEccsiHash(&userEccsi, hashId, hashIdSz);
    if (ret == 0)
        ret = wc_VerifyEccsiHash(&userEccsi, WC_HASH_TYPE_SHA256, payload,
                                 SSV_SZ + authSz, sig, sigSz, &verified);
    if (ret != 0 || !verified) {
        printf("ECCSI verify failed: ret %d verified %d\n", ret, verified);
        ret = -1;
        goto exit;
    }
    printf("Bob: ECCSI signature from '%s' verified\n",
           (const char*)aliceId);

    /* Derivation unmasks the SSV in place and validates it against auth. */
    ret = wc_SetSakkeRsk(&userSakke, rsk, NULL, 0);
    if (ret == 0)
        ret = wc_DeriveSakkeSSV(&userSakke, WC_HASH_TYPE_SHA256, payload,
                                SSV_SZ, payload + SSV_SZ, authSz);
    if (ret != 0) {
        printf("wc_DeriveSakkeSSV failed %d\n", ret);
        goto exit;
    }
    print_hex("Bob:   SSV", payload, SSV_SZ);

    if (memcmp(ssv, payload, SSV_SZ) != 0) {
        printf("SSVs differ!\n");
        ret = -1;
        goto exit;
    }
    printf("Shared Secret Values match\n");
    ret = 0;

exit:
    if (ret != 0)
        printf("error %d: %s\n", ret, wc_GetErrorString(ret));
    if (rsk != NULL)
        wc_ecc_forcezero_point(rsk);
    if (pvt != NULL)
        wc_ecc_del_point(pvt);
    if (rsk != NULL)
        wc_ecc_del_point(rsk);
    if (sskInit)
        mp_forcezero(&ssk);
    if (userSakkeInit)
        wc_FreeSakkeKey(&userSakke);
    if (kmsSakkeInit)
        wc_FreeSakkeKey(&kmsSakke);
    if (userEccsiInit)
        wc_FreeEccsiKey(&userEccsi);
    if (kmsEccsiInit)
        wc_FreeEccsiKey(&kmsEccsi);
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
