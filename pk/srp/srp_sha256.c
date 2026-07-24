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
    Srp    cli;
    Srp    srv;
    int    cliInit = 0;
    int    srvInit = 0;
    byte   salt[SALT_SZ];
    byte   verifier[KEY_BUF_SZ];
    word32 verifierSz = (word32)sizeof(verifier);
    byte   clientPub[KEY_BUF_SZ];
    word32 clientPubSz = (word32)sizeof(clientPub);
    byte   serverPub[KEY_BUF_SZ];
    word32 serverPubSz = (word32)sizeof(serverPub);
    byte   proof[PROOF_SZ];
    word32 proofSz = (word32)sizeof(proof);
    const char* username = "alice";
    const char* password = "password123";

    ret = wc_InitRng(&rng);
    if (ret != 0) {
        printf("wc_InitRng failed %d\n", ret);
        goto exit;
    }
    rngInit = 1;

    /* Enrollment: random salt, then a client-side object derives the
     * verifier the server will store. */
    ret = wc_RNG_GenerateBlock(&rng, salt, sizeof(salt));
    if (ret != 0)
        goto exit;

    ret = wc_SrpInit(&cli, SRP_TYPE_SHA256, SRP_CLIENT_SIDE);
    if (ret != 0)
        goto exit;
    cliInit = 1;

    ret = wc_SrpSetUsername(&cli, (const byte*)username,
                            (word32)strlen(username));
    if (ret == 0)
        ret = wc_SrpSetParams(&cli, srp_n_2048, sizeof(srp_n_2048),
                              srp_g_2048, sizeof(srp_g_2048), salt,
                              sizeof(salt));
    if (ret == 0)
        ret = wc_SrpSetPassword(&cli, (const byte*)password,
                                (word32)strlen(password));
    if (ret == 0)
        ret = wc_SrpGetVerifier(&cli, verifier, &verifierSz);
    if (ret != 0) {
        printf("verifier generation failed %d\n", ret);
        goto exit;
    }
    printf("Enrolled user '%s' (verifier %u bytes)\n", username, verifierSz);

    /* Login: client computes its public key A. The enrollment object is
     * reused; a real client would build a fresh one the same way. */
    ret = wc_SrpGetPublic(&cli, clientPub, &clientPubSz);
    if (ret != 0) {
        printf("client wc_SrpGetPublic failed %d\n", ret);
        goto exit;
    }

    /* Server loads the stored verifier and computes its public key B. */
    ret = wc_SrpInit(&srv, SRP_TYPE_SHA256, SRP_SERVER_SIDE);
    if (ret != 0)
        goto exit;
    srvInit = 1;

    ret = wc_SrpSetUsername(&srv, (const byte*)username,
                            (word32)strlen(username));
    if (ret == 0)
        ret = wc_SrpSetParams(&srv, srp_n_2048, sizeof(srp_n_2048),
                              srp_g_2048, sizeof(srp_g_2048), salt,
                              sizeof(salt));
    if (ret == 0)
        ret = wc_SrpSetVerifier(&srv, verifier, verifierSz);
    if (ret == 0)
        ret = wc_SrpGetPublic(&srv, serverPub, &serverPubSz);
    if (ret != 0) {
        printf("server setup failed %d\n", ret);
        goto exit;
    }

    /* Both sides derive the session key from the two public keys. */
    ret = wc_SrpComputeKey(&cli, clientPub, clientPubSz, serverPub,
                           serverPubSz);
    if (ret == 0)
        ret = wc_SrpComputeKey(&srv, clientPub, clientPubSz, serverPub,
                               serverPubSz);
    if (ret != 0) {
        printf("wc_SrpComputeKey failed %d\n", ret);
        goto exit;
    }

    /* Client proves first; only then does the server prove back. */
    ret = wc_SrpGetProof(&cli, proof, &proofSz);
    if (ret == 0)
        ret = wc_SrpVerifyPeersProof(&srv, proof, proofSz);
    if (ret != 0) {
        printf("server rejected client proof %d\n", ret);
        goto exit;
    }
    printf("Server verified client proof\n");

    proofSz = (word32)sizeof(proof);
    ret = wc_SrpGetProof(&srv, proof, &proofSz);
    if (ret == 0)
        ret = wc_SrpVerifyPeersProof(&cli, proof, proofSz);
    if (ret != 0) {
        printf("client rejected server proof %d\n", ret);
        goto exit;
    }
    printf("Client verified server proof\n");

    if (cli.keySz != srv.keySz ||
            memcmp(cli.key, srv.key, cli.keySz) != 0) {
        printf("Session keys differ!\n");
        ret = -1;
        goto exit;
    }
    print_hex("session key", cli.key, cli.keySz);
    printf("Session keys match\n");
    ret = 0;

exit:
    if (srvInit)
        wc_SrpTerm(&srv);
    if (cliInit)
        wc_SrpTerm(&cli);
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
