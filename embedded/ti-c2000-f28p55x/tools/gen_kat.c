/* gen_kat.c
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
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


/* Generate the deterministic ML-DSA KAT vectors in Header/mldsa_octet_kat.h.
 *
 *   gcc -o gen_kat gen_kat.c -lwolfssl && ./gen_kat && mv mldsa_octet_kat.h ../Header/
 *
 * Everything is seed driven, so a regeneration reproduces the file exactly. */
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/wc_mldsa.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/sha512.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <stdio.h>

#define MSG_SZ   512
#define OUT_NAME "mldsa_octet_kat.h"

static const byte kSeed[MLDSA_SEED_SZ] = {
    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
    0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
    0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
    0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
};
static const byte kRnd[MLDSA_RND_SZ] = {
    0xa0,0xa1,0xa2,0xa3,0xa4,0xa5,0xa6,0xa7,
    0xa8,0xa9,0xaa,0xab,0xac,0xad,0xae,0xaf,
    0xb0,0xb1,0xb2,0xb3,0xb4,0xb5,0xb6,0xb7,
    0xb8,0xb9,0xba,0xbb,0xbc,0xbd,0xbe,0xbf
};
/* FIPS 204 application context string; deliberately non-empty so the
 * 0x01 || ctxLen || ctx domain separator is actually exercised. */
static const char kCtx[] = "wolfSSL-C28x";

static FILE* out;

static void emit_bytes(const char* name, const byte* b, word32 len)
{
    word32 i;
    fprintf(out, "static const unsigned char %s[] = {", name);
    for (i = 0; i < len; i++) {
        fprintf(out, "%s 0x%02x,", ((i % 12) == 0) ? "\n   " : "", b[i]);
    }
    fprintf(out, "\n};\n");
}

/* Same octets packed two per 16-bit cell, low octet first.  Identical storage
 * on a little-endian 8-bit host, so the same test code runs on both. */
static void emit_packed(const char* name, const byte* b, word32 len)
{
    word32 cells = (len + 1) / 2;
    word32 i;
    fprintf(out, "static const unsigned short %s[] = {", name);
    for (i = 0; i < cells; i++) {
        unsigned lo = b[i * 2];
        unsigned hi = ((i * 2 + 1) < len) ? b[i * 2 + 1] : 0;
        fprintf(out, "%s 0x%04x,", ((i % 8) == 0) ? "\n   " : "",
            lo | (hi << 8));
    }
    fprintf(out, "\n};\n");
}

static int do_level(int type, const char* tag, const byte* msg,
    const byte* sha256, const byte* sha512, int wantPacked, int wantPh512)
{
    wc_MlDsaKey key;
    byte  pub[MLDSA_MAX_PUB_KEY_SIZE];
    byte  sig[MLDSA_MAX_SIG_SIZE];
    word32 pubLen = (word32)sizeof(pub);
    word32 sigLen;
    char  name[64];
    int   ret;

    ret = wc_MlDsaKey_Init(&key, NULL, INVALID_DEVID);
    if (ret != 0) {
        fprintf(stderr, "%s init failed: %d\n", tag, ret);
        return ret;
    }

    ret = wc_MlDsaKey_SetParams(&key, type);
    if (ret == 0)
        ret = wc_MlDsaKey_MakeKeyFromSeed(&key, kSeed);
    if (ret == 0)
        ret = wc_MlDsaKey_ExportPubRaw(&key, pub, &pubLen);
    if (ret == 0) {
        snprintf(name, sizeof(name), "kat_mldsa%s_pub", tag);
        emit_bytes(name, pub, pubLen);
    }

    /* Plain (non pre-hash) signature over the whole message. */
    if (ret == 0) {
        sigLen = (word32)sizeof(sig);
        ret = wc_MlDsaKey_SignCtxWithSeed(&key, NULL, 0, sig, &sigLen,
            msg, MSG_SZ, kRnd);
    }
    if (ret == 0) {
        snprintf(name, sizeof(name), "kat_mldsa%s_sig", tag);
        emit_bytes(name, sig, sigLen);
        if (wantPacked) {
            snprintf(name, sizeof(name), "kat_mldsa%s_sig_packed", tag);
            emit_packed(name, sig, sigLen);
            snprintf(name, sizeof(name), "kat_mldsa%s_pub_packed", tag);
            emit_packed(name, pub, pubLen);
        }
    }

    /* HashML-DSA over SHA-256(msg) with a non-empty context. */
    if (ret == 0) {
        sigLen = (word32)sizeof(sig);
        ret = wc_MlDsaKey_SignCtxHashWithSeed(&key, (const byte*)kCtx,
            (byte)(sizeof(kCtx) - 1), sig, &sigLen, sha256,
            WC_SHA256_DIGEST_SIZE, WC_HASH_TYPE_SHA256, kRnd);
    }
    if (ret == 0) {
        snprintf(name, sizeof(name), "kat_mldsa%s_sig_ph256", tag);
        emit_bytes(name, sig, sigLen);
    }

    /* Same again over SHA-512, so the OID table is exercised at two lengths. */
    if ((ret == 0) && wantPh512) {
        sigLen = (word32)sizeof(sig);
        ret = wc_MlDsaKey_SignCtxHashWithSeed(&key, (const byte*)kCtx,
            (byte)(sizeof(kCtx) - 1), sig, &sigLen, sha512,
            WC_SHA512_DIGEST_SIZE, WC_HASH_TYPE_SHA512, kRnd);
        if (ret == 0) {
            snprintf(name, sizeof(name), "kat_mldsa%s_sig_ph512", tag);
            emit_bytes(name, sig, sigLen);
        }
    }

    if (ret != 0)
        fprintf(stderr, "%s vector generation failed: %d\n", tag, ret);

    wc_MlDsaKey_Free(&key);
    return ret;
}

int main(void)
{
    byte msg[MSG_SZ];
    byte sha256[WC_SHA256_DIGEST_SIZE];
    byte sha512[WC_SHA512_DIGEST_SIZE];
    int  i;
    int  ret;

    for (i = 0; i < MSG_SZ; i++)
        msg[i] = (byte)(i & 0xFF);

    ret = wolfCrypt_Init();
    if (ret != 0) {
        fprintf(stderr, "wolfCrypt_Init failed: %d\n", ret);
        return 1;
    }

    ret = wc_Sha256Hash(msg, MSG_SZ, sha256);
    if (ret == 0)
        ret = wc_Sha512Hash(msg, MSG_SZ, sha512);
    if (ret != 0) {
        fprintf(stderr, "hash failed: %d\n", ret);
        wolfCrypt_Cleanup();
        return 1;
    }

    out = fopen(OUT_NAME, "w");
    if (out == NULL) {
        fprintf(stderr, "cannot open output\n");
        wolfCrypt_Cleanup();
        return 1;
    }

    fprintf(out,
        "/* ML-DSA octet-boundary KAT vectors for the TI C2000 C28x example.\n"
        " *\n"
        " * GENERATED by tools/gen_kat.c - do not edit.  Seed driven, so a\n"
        " * regeneration reproduces this file exactly.  Message is\n"
        " * msg[i] = i & 0xFF, 512 octets.  The _packed arrays hold the same\n"
        " * octets two per 16-bit cell, low octet first - the layout an octet\n"
        " * stream has off flash on a CHAR_BIT == 16 target. */\n"
        "#ifndef MLDSA_OCTET_KAT_H\n"
        "#define MLDSA_OCTET_KAT_H\n\n"
        "#define KAT_MLDSA_CTX  \"%s\"\n\n", kCtx);

    ret = do_level(WC_ML_DSA_44, "44", msg, sha256, sha512, 0, 0);
    if (ret == 0)
        ret = do_level(WC_ML_DSA_65, "65", msg, sha256, sha512, 1, 0);
    if (ret == 0)
        ret = do_level(WC_ML_DSA_87, "87", msg, sha256, sha512, 0, 1);

    if (ret == 0)
        fprintf(out, "\n#endif /* MLDSA_OCTET_KAT_H */\n");
    fclose(out);
    if (ret != 0) {
        /* Do not leave a truncated header behind for the build to pick up. */
        remove(OUT_NAME);
        wolfCrypt_Cleanup();
        return 1;
    }
    wolfCrypt_Cleanup();
    return 0;
}
