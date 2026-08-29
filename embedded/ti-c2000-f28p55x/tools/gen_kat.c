/* Generate deterministic ML-DSA KAT vectors for the TI C2000 C28x example.
 * Emits Header/mldsa_octet_kat.h.  Everything here is seed driven, so the
 * header regenerates byte for byte. */
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/wc_mldsa.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/sha512.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <stdio.h>
#include <string.h>

#define MSG_SZ  512

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
    fprintf(out, "static const unsigned char %s[] = {\n   ", name);
    for (i = 0; i < len; i++) {
        fprintf(out, " 0x%02x,", b[i]);
        if ((i % 12) == 11)
            fprintf(out, "\n   ");
    }
    fseek(out, -1, SEEK_CUR);
    fprintf(out, "\n};\n");
}

/* Same octets, but PACKED two per 16-bit cell, low octet first - the layout an
 * octet stream has when it arrives from flash or a byte oriented link on a
 * CHAR_BIT == 16 target.  On a little endian 8-bit host the storage is
 * identical, which is what makes the same test code run on both. */
static void emit_packed(const char* name, const byte* b, word32 len)
{
    word32 i;
    word32 cells = (len + 1) / 2;
    fprintf(out, "static const unsigned short %s[] = {\n   ", name);
    for (i = 0; i < cells; i++) {
        unsigned lo = b[i * 2];
        unsigned hi = ((i * 2 + 1) < len) ? b[i * 2 + 1] : 0;
        fprintf(out, " 0x%04x,", lo | (hi << 8));
        if ((i % 8) == 7)
            fprintf(out, "\n   ");
    }
    fseek(out, -1, SEEK_CUR);
    fprintf(out, "\n};\n");
}

static int do_level(int type, const char* tag, const byte* msg,
    const byte* sha256, const byte* sha512, int wantPacked)
{
    wc_MlDsaKey key;
    byte  pub[MLDSA_MAX_PUB_KEY_SIZE];
    byte  sig[MLDSA_MAX_SIG_SIZE];
    word32 pubLen = (word32)sizeof(pub);
    word32 sigLen;
    char  name[64];
    int   ret;

    ret = wc_MlDsaKey_Init(&key, NULL, INVALID_DEVID);
    if (ret == 0)
        ret = wc_MlDsaKey_SetParams(&key, type);
    if (ret == 0)
        ret = wc_MlDsaKey_MakeKeyFromSeed(&key, kSeed);
    if (ret == 0)
        ret = wc_MlDsaKey_ExportPubRaw(&key, pub, &pubLen);
    if (ret != 0) {
        fprintf(stderr, "%s keygen failed: %d\n", tag, ret);
        return ret;
    }
    snprintf(name, sizeof(name), "kat_mldsa%s_pub", tag);
    emit_bytes(name, pub, pubLen);

    /* Plain (non pre-hash) signature over the whole message. */
    sigLen = (word32)sizeof(sig);
    ret = wc_MlDsaKey_SignCtxWithSeed(&key, NULL, 0, sig, &sigLen,
        msg, MSG_SZ, kRnd);
    if (ret != 0) {
        fprintf(stderr, "%s sign failed: %d\n", tag, ret);
        return ret;
    }
    snprintf(name, sizeof(name), "kat_mldsa%s_sig", tag);
    emit_bytes(name, sig, sigLen);
    if (wantPacked) {
        snprintf(name, sizeof(name), "kat_mldsa%s_sig_packed", tag);
        emit_packed(name, sig, sigLen);
        snprintf(name, sizeof(name), "kat_mldsa%s_pub_packed", tag);
        emit_packed(name, pub, pubLen);
    }

    /* HashML-DSA over SHA-256(msg) with a non-empty context - the exact shape
     * of wc_MlDsaKey_VerifyCtxHash(). */
    sigLen = (word32)sizeof(sig);
    ret = wc_MlDsaKey_SignCtxHashWithSeed(&key, (const byte*)kCtx,
        (byte)(sizeof(kCtx) - 1), sig, &sigLen, sha256, WC_SHA256_DIGEST_SIZE,
        WC_HASH_TYPE_SHA256, kRnd);
    if (ret != 0) {
        fprintf(stderr, "%s ctxhash sha256 sign failed: %d\n", tag, ret);
        return ret;
    }
    snprintf(name, sizeof(name), "kat_mldsa%s_sig_ph256", tag);
    emit_bytes(name, sig, sigLen);

    /* Same again over SHA-512, so the OID table is exercised at two lengths. */
    sigLen = (word32)sizeof(sig);
    ret = wc_MlDsaKey_SignCtxHashWithSeed(&key, (const byte*)kCtx,
        (byte)(sizeof(kCtx) - 1), sig, &sigLen, sha512, WC_SHA512_DIGEST_SIZE,
        WC_HASH_TYPE_SHA512, kRnd);
    if (ret != 0) {
        fprintf(stderr, "%s ctxhash sha512 sign failed: %d\n", tag, ret);
        return ret;
    }
    snprintf(name, sizeof(name), "kat_mldsa%s_sig_ph512", tag);
    emit_bytes(name, sig, sigLen);

    wc_MlDsaKey_Free(&key);
    return 0;
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

    ret = wc_Sha256Hash(msg, MSG_SZ, sha256);
    if (ret == 0)
        ret = wc_Sha512Hash(msg, MSG_SZ, sha512);
    if (ret != 0) {
        fprintf(stderr, "hash failed: %d\n", ret);
        return 1;
    }

    out = fopen("mldsa_octet_kat.h", "w");
    if (out == NULL) {
        fprintf(stderr, "cannot open output\n");
        return 1;
    }

    fprintf(out,
        "/* ML-DSA octet-boundary KAT vectors for the TI C2000 C28x example.\n"
        " *\n"
        " * GENERATED - do not edit by hand.  Produced by gen_kat.c against a\n"
        " * wolfSSL host build; every value is seed driven so a regeneration\n"
        " * reproduces this file exactly.\n"
        " *\n"
        " * Keys come from wc_MlDsaKey_MakeKeyFromSeed() with a fixed 32 octet\n"
        " * seed; signatures from wc_MlDsaKey_SignCtx*WithSeed() with a fixed\n"
        " * 32 octet rnd.  The message is msg[i] = i & 0xFF, 512 octets, the\n"
        " * same one wolfcrypt/test/test.c uses.\n"
        " *\n"
        " * The _packed arrays hold the same octets two per 16-bit cell, low\n"
        " * octet first: the layout an octet stream has coming off flash or a\n"
        " * byte oriented link on a CHAR_BIT == 16 target.  wc_UnpackOctets()\n"
        " * converts them to the one-octet-per-cell form the APIs take. */\n"
        "#ifndef MLDSA_OCTET_KAT_H\n"
        "#define MLDSA_OCTET_KAT_H\n\n"
        "#define KAT_MLDSA_CTX  \"%s\"\n\n", kCtx);

    ret = do_level(WC_ML_DSA_44, "44", msg, sha256, sha512, 0);
    if (ret == 0)
        ret = do_level(WC_ML_DSA_65, "65", msg, sha256, sha512, 1);
    if (ret == 0)
        ret = do_level(WC_ML_DSA_87, "87", msg, sha256, sha512, 0);

    fprintf(out, "\n#endif /* MLDSA_OCTET_KAT_H */\n");
    fclose(out);
    return (ret == 0) ? 0 : 1;
}
