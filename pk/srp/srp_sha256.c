/* srp_sha256.c
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

/* Example of a full SRP-6a exchange using SHA-256 and the RFC 5054 2048-bit
 * group. Both sides run in this one program:
 *
 *   enrollment: client derives a verifier from the password; server stores
 *               (username, salt, verifier) and never sees the password.
 *   login:      both sides exchange public keys, compute the session key,
 *               and prove knowledge of it to each other. */

#include <stdio.h>
#include <string.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/srp.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#ifdef WOLFCRYPT_HAVE_SRP

#include "srp_params_2048.h"

#define SALT_SZ     16
#define KEY_BUF_SZ  256
#define PROOF_SZ    64

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

    WC_RNG rng;
    int    rngInit = 0;

    /* Shared by both sides: the client picks it at enrollment and the server
     * keeps it alongside the verifier. */
    byte   salt[SALT_SZ];

    /* Every struct below is declared before the first "goto exit" so that the
     * cleanup at the bottom always sees initialised members. */
    struct {
        Srp         cli;
        int         cliInit;
        byte        clientPub[KEY_BUF_SZ];  /* A, sent to the server */
        word32      clientPubSz;
        const char* username;
        const char* password;              /* never leaves the client */
        byte        proof[PROOF_SZ];        /* M1 */
        word32      proofSz;
        byte        verifier[KEY_BUF_SZ];   /* derived from the password */
        word32      verifierSz;
    } client = {0};

    struct {
        Srp         srv;
        int         srvInit;
        byte        serverPub[KEY_BUF_SZ];  /* B, sent to the client */
        word32      serverPubSz;
        const char* username;               /* the stored record: no password */
        byte        proof[PROOF_SZ];        /* M2 */
        word32      proofSz;
        byte        verifier[KEY_BUF_SZ];
        word32      verifierSz;
    } server = {0};

    client.username = "alice";
    client.password = "password123";

    /* --- One RNG instance for simplicity --- */
    ret = wc_InitRng(&rng);
    if (ret != 0) {
        printf("wc_InitRng failed %d\n", ret);
        goto exit;
    }
    rngInit = 1;
    /* --- One RNG instance for simplicity --- */

    /* --- Enrollment: random salt, then a client-side object derives the
     * verifier the server will store. --- */
    ret = wc_RNG_GenerateBlock(&rng, salt, sizeof(salt));
    if (ret != 0) {
        printf("salt generation failed %d\n", ret);
        goto exit;
    }

    ret = wc_SrpInit(&client.cli, SRP_TYPE_SHA256, SRP_CLIENT_SIDE);
    if (ret != 0) goto exit; else client.cliInit = 1;

    ret = wc_SrpSetUsername(&client.cli, (const byte*)client.username,
                            (word32)strlen(client.username));
    if (ret == 0)
        ret = wc_SrpSetParams(&client.cli, srp_n_2048, sizeof(srp_n_2048),
                              srp_g_2048, sizeof(srp_g_2048), salt,
                              sizeof(salt));
    if (ret == 0)
        ret = wc_SrpSetPassword(&client.cli, (const byte*)client.password,
                                (word32)strlen(client.password));
    if (ret == 0) {
        client.verifierSz = (word32)sizeof(client.verifier);
        ret = wc_SrpGetVerifier(&client.cli, client.verifier,
                                &client.verifierSz);
    }
    if (ret != 0) {
        printf("verifier generation failed %d\n", ret);
        goto exit;
    }
    printf("Enrolled user '%s' (verifier %u bytes)\n", client.username,
           client.verifierSz);
    /* --- Enrollment --- */

    /* --- Hand the record to the server; the password stays behind --- */
    server.username   = client.username;
    server.verifierSz = client.verifierSz;
    memcpy(server.verifier, client.verifier, server.verifierSz);
    /* --- Hand the record to the server; the password stays behind --- */

    /* --- Login: client computes its public key A. The enrollment object is
     * reused; a real client would build a fresh one the same way. --- */
    client.clientPubSz = (word32)sizeof(client.clientPub);
    ret = wc_SrpGetPublic(&client.cli, client.clientPub, &client.clientPubSz);
    if (ret != 0) {
        printf("client wc_SrpGetPublic failed %d\n", ret);
        goto exit;
    }
    /* --- Login: client public key A --- */

    /* --- Server loads the stored verifier and computes its public key B --- */
    ret = wc_SrpInit(&server.srv, SRP_TYPE_SHA256, SRP_SERVER_SIDE);
    if (ret != 0) goto exit; else server.srvInit = 1;

    ret = wc_SrpSetUsername(&server.srv, (const byte*)server.username,
                            (word32)strlen(server.username));
    if (ret == 0)
        ret = wc_SrpSetParams(&server.srv, srp_n_2048, sizeof(srp_n_2048),
                              srp_g_2048, sizeof(srp_g_2048), salt,
                              sizeof(salt));
    if (ret == 0)
        ret = wc_SrpSetVerifier(&server.srv, server.verifier,
                                server.verifierSz);
    if (ret == 0) {
        server.serverPubSz = (word32)sizeof(server.serverPub);
        ret = wc_SrpGetPublic(&server.srv, server.serverPub,
                              &server.serverPubSz);
    }
    if (ret != 0) {
        printf("server setup failed %d\n", ret);
        goto exit;
    }
    /* --- Server public key B --- */

    /* --- Both sides derive the session key from the two public keys --- */
    ret = wc_SrpComputeKey(&client.cli, client.clientPub, client.clientPubSz,
                           server.serverPub, server.serverPubSz);
    if (ret == 0)
        ret = wc_SrpComputeKey(&server.srv, client.clientPub,
                               client.clientPubSz, server.serverPub,
                               server.serverPubSz);
    if (ret != 0) {
        printf("wc_SrpComputeKey failed %d\n", ret);
        goto exit;
    }
    /* --- Both sides derive the session key --- */

    /* --- Client proves first; only then does the server prove back --- */
    client.proofSz = (word32)sizeof(client.proof);
    ret = wc_SrpGetProof(&client.cli, client.proof, &client.proofSz);
    if (ret == 0)
        ret = wc_SrpVerifyPeersProof(&server.srv, client.proof,
                                     client.proofSz);
    if (ret != 0) {
        printf("server rejected client proof %d\n", ret);
        goto exit;
    }
    printf("Server verified client proof\n");

    server.proofSz = (word32)sizeof(server.proof);
    ret = wc_SrpGetProof(&server.srv, server.proof, &server.proofSz);
    if (ret == 0)
        ret = wc_SrpVerifyPeersProof(&client.cli, server.proof,
                                     server.proofSz);
    if (ret != 0) {
        printf("client rejected server proof %d\n", ret);
        goto exit;
    }
    printf("Client verified server proof\n");
    /* --- Client proves first; only then does the server prove back --- */

    if (client.cli.keySz != server.srv.keySz ||
            memcmp(client.cli.key, server.srv.key, client.cli.keySz) != 0) {
        printf("Session keys differ!\n");
        ret = -1;
        goto exit;
    }
    print_hex("session key", client.cli.key, client.cli.keySz);
    printf("Session keys match\n");
    ret = 0;

exit:
    if (ret != 0)
        printf("error %d: %s\n", ret, wc_GetErrorString(ret));

    if (server.srvInit)
        wc_SrpTerm(&server.srv);
    if (client.cliInit)
        wc_SrpTerm(&client.cli);
    if (rngInit)
        wc_FreeRng(&rng);

    return ret == 0 ? 0 : 1;
}

#else

int main(void)
{
    printf("Please build wolfSSL with ./configure --enable-srp\n");
    return 0;
}

#endif /* WOLFCRYPT_HAVE_SRP */
