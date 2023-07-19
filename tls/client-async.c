/* client-async.c
 *
 * Copyright (C) 2006-2023 wolfSSL Inc.
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

/* Version that demonstrates Asynchronous Crypt features
 *
 * Tested with:
./configure --enable-asynccrypt --disable-rsa
./configure --enable-asynccrypt
./configure --enable-asynccrypt --enable-cryptocb
./configure --enable-asynccrypt --enable-cryptocb --disable-rsa
make
sudo make install
 * Requires: https://github.com/wolfSSL/wolfAsyncCrypt
 *
 * Example:
 ./server-async
 ./client-async 127.0.0.1
*/

/* the usual suspects */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/* socket includes */
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>

/* wolfSSL */
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfio.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#define DEFAULT_PORT 11111
#define TEST_BUF_SZ  256

#ifndef NO_RSA
    #define CERT_FILE "../certs/client-cert.pem"
    #define KEY_FILE  "../certs/client-key.pem"
    #define CA_FILE   "../certs/ca-cert.pem"
#elif defined(HAVE_ECC)
    #define CERT_FILE "../certs/client-ecc-cert.pem"
    #define KEY_FILE  "../certs/ecc-client-key.pem"
    #define CA_FILE   "../certs/ca-ecc-cert.pem"
#else
    #error No authentication algorithm (ECC/RSA)
#endif

#ifdef WOLF_CRYPTO_CB

/* Example custom context for crypto callback */
#define TEST_PEND_COUNT 5
typedef struct {
    int pendingCount; /* track pending tries test count */
} myCryptoCbCtx;

/* Example crypto dev callback function that calls software version */
/* This is where you would plug-in calls to your own hardware crypto */
static int myCryptoCb(int devIdArg, wc_CryptoInfo* info, void* ctx)
{
    int ret = CRYPTOCB_UNAVAILABLE; /* return this to bypass HW and use SW */
    myCryptoCbCtx* myCtx = (myCryptoCbCtx*)ctx;

    if (info == NULL)
        return BAD_FUNC_ARG;

#ifdef DEBUG_CRYPTOCB
    wc_CryptoCb_InfoString(info);
#endif

    if (info->algo_type == WC_ALGO_TYPE_PK) {
#ifdef WOLFSSL_ASYNC_CRYPT
        /* workaround for crypto callback with async */
    #ifndef NO_RSA
        if (info->pk.type == WC_PK_TYPE_RSA)
            wc_AsyncSwInit(&info->pk.rsa.key->asyncDev, ASYNC_SW_RSA_FUNC);
    #endif
    #ifdef HAVE_ECC
        if (info->pk.type == WC_PK_TYPE_EC_KEYGEN)
            wc_AsyncSwInit(&info->pk.eckg.key->asyncDev, ASYNC_SW_ECC_MAKE);
        else if (info->pk.type == WC_PK_TYPE_ECDSA_SIGN)
            wc_AsyncSwInit(&info->pk.eccsign.key->asyncDev, ASYNC_SW_ECC_SIGN);
        else if (info->pk.type == WC_PK_TYPE_ECDSA_VERIFY)
            wc_AsyncSwInit(&info->pk.eccverify.key->asyncDev,
                ASYNC_SW_ECC_VERIFY);
        else if (info->pk.type == WC_PK_TYPE_ECDH)
            wc_AsyncSwInit(&info->pk.ecdh.private_key->asyncDev,
                ASYNC_SW_ECC_SHARED_SEC);
    #endif

        /* Test pending response */
        if (info->pk.type == WC_PK_TYPE_RSA ||
            info->pk.type == WC_PK_TYPE_EC_KEYGEN ||
            info->pk.type == WC_PK_TYPE_ECDSA_SIGN ||
            info->pk.type == WC_PK_TYPE_ECDSA_VERIFY ||
            info->pk.type == WC_PK_TYPE_ECDH)
        {
            if (myCtx->pendingCount++ < TEST_PEND_COUNT) return WC_PENDING_E;
            myCtx->pendingCount = 0;
        }
#endif

    #ifndef NO_RSA
        if (info->pk.type == WC_PK_TYPE_RSA) {
            /* set devId to invalid, so software is used */
            info->pk.rsa.key->devId = INVALID_DEVID;

            switch (info->pk.rsa.type) {
                case RSA_PUBLIC_ENCRYPT:
                case RSA_PUBLIC_DECRYPT:
                    /* perform software based RSA public op */
                    ret = wc_RsaFunction(
                        info->pk.rsa.in, info->pk.rsa.inLen,
                        info->pk.rsa.out, info->pk.rsa.outLen,
                        info->pk.rsa.type, info->pk.rsa.key, info->pk.rsa.rng);
                    break;
                case RSA_PRIVATE_ENCRYPT:
                case RSA_PRIVATE_DECRYPT:
                    /* perform software based RSA private op */
                    ret = wc_RsaFunction(
                        info->pk.rsa.in, info->pk.rsa.inLen,
                        info->pk.rsa.out, info->pk.rsa.outLen,
                        info->pk.rsa.type, info->pk.rsa.key, info->pk.rsa.rng);
                    break;
            }

            /* reset devId */
            info->pk.rsa.key->devId = devIdArg;
        }
    #endif
    #ifdef HAVE_ECC
        if (info->pk.type == WC_PK_TYPE_EC_KEYGEN) {
            /* set devId to invalid, so software is used */
            info->pk.eckg.key->devId = INVALID_DEVID;

            ret = wc_ecc_make_key_ex(info->pk.eckg.rng, info->pk.eckg.size,
                info->pk.eckg.key, info->pk.eckg.curveId);

            /* reset devId */
            info->pk.eckg.key->devId = devIdArg;
        }
        else if (info->pk.type == WC_PK_TYPE_ECDSA_SIGN) {
            /* set devId to invalid, so software is used */
            info->pk.eccsign.key->devId = INVALID_DEVID;

            ret = wc_ecc_sign_hash(
                info->pk.eccsign.in, info->pk.eccsign.inlen,
                info->pk.eccsign.out, info->pk.eccsign.outlen,
                info->pk.eccsign.rng, info->pk.eccsign.key);

            /* reset devId */
            info->pk.eccsign.key->devId = devIdArg;
        }
        else if (info->pk.type == WC_PK_TYPE_ECDSA_VERIFY) {
            /* set devId to invalid, so software is used */
            info->pk.eccverify.key->devId = INVALID_DEVID;

            ret = wc_ecc_verify_hash(
                info->pk.eccverify.sig, info->pk.eccverify.siglen,
                info->pk.eccverify.hash, info->pk.eccverify.hashlen,
                info->pk.eccverify.res, info->pk.eccverify.key);

            /* reset devId */
            info->pk.eccverify.key->devId = devIdArg;
        }
        else if (info->pk.type == WC_PK_TYPE_ECDH) {
            /* set devId to invalid, so software is used */
            info->pk.ecdh.private_key->devId = INVALID_DEVID;

            ret = wc_ecc_shared_secret(
                info->pk.ecdh.private_key, info->pk.ecdh.public_key,
                info->pk.ecdh.out, info->pk.ecdh.outlen);

            /* reset devId */
            info->pk.ecdh.private_key->devId = devIdArg;
        }
    #endif /* HAVE_ECC */
    }

    (void)devIdArg;
    (void)myCtx;

    return ret;
}
#endif /* WOLF_CRYPTO_CB */

int main(int argc, char** argv)
{
    int ret = 0;
    int                sockfd = SOCKET_INVALID;
    struct sockaddr_in servAddr;
    char               buff[TEST_BUF_SZ];
    size_t             len;
    int                devId = 1; /* anything besides -2 (INVALID_DEVID) */
#ifdef WOLF_CRYPTO_CB
    myCryptoCbCtx      myCtx;
#endif
    int  err;
    char errBuff[WOLFSSL_MAX_ERROR_SZ];

    /* declare wolfSSL objects */
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL*     ssl = NULL;

    /* Check for proper calling convention */
    if (argc != 2) {
        printf("usage: %s <IPv4 address>\n", argv[0]);
        return 0;
    }

    /* Create a socket that uses an internet IPv4 address,
     * Sets the socket to be stream based (TCP),
     * 0 means choose the default protocol. */
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        fprintf(stderr, "ERROR: failed to create the socket\n");
        ret = -1; goto exit;
    }

    /* Initialize the server address struct with zeros */
    memset(&servAddr, 0, sizeof(servAddr));

    /* Fill in the server address */
    servAddr.sin_family = AF_INET;             /* using IPv4      */
    servAddr.sin_port   = htons(DEFAULT_PORT); /* on DEFAULT_PORT */

    /* Get the server IPv4 address from the command line call */
    if (inet_pton(AF_INET, argv[1], &servAddr.sin_addr) != 1) {
        fprintf(stderr, "ERROR: invalid address\n");
        ret = -1; goto exit;
    }

    /* Connect to the server */
    if ((ret = connect(sockfd, (struct sockaddr*) &servAddr, sizeof(servAddr)))
         == -1) {
        fprintf(stderr, "ERROR: failed to connect\n");
        goto exit;
    }

    /*---------------------------------*/
    /* Start of wolfSSL initialization and configuration */
    /*---------------------------------*/
#if 1
    wolfSSL_Debugging_ON();
#endif

    /* Initialize wolfSSL */
    if ((ret = wolfSSL_Init()) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "ERROR: Failed to initialize the library\n");
        goto exit;
    }

    /* Create and initialize WOLFSSL_CTX */
    if ((ctx = wolfSSL_CTX_new(wolfSSLv23_client_method())) == NULL) {
        fprintf(stderr, "ERROR: failed to create WOLFSSL_CTX\n");
        ret = -1; goto exit;
    }

#ifdef WOLF_CRYPTO_CB
    XMEMSET(&myCtx, 0, sizeof(myCtx));
    /* register a devID for crypto callbacks */
    ret = wc_CryptoCb_RegisterDevice(devId, myCryptoCb, &myCtx);
    if (ret != 0) {
        fprintf(stderr, "wc_CryptoCb_RegisterDevice: error %d", ret);
        goto exit;
    }
#endif
    /* register a devID for crypto callbacks */
    wolfSSL_CTX_SetDevId(ctx, devId);

    /* Load client certificate into WOLFSSL_CTX */
    if ((ret = wolfSSL_CTX_use_certificate_file(ctx, CERT_FILE, WOLFSSL_FILETYPE_PEM))
        != WOLFSSL_SUCCESS) {
        fprintf(stderr, "ERROR: failed to load %s, please check the file.\n",
                CERT_FILE);
        goto exit;
    }

    /* Load client key into WOLFSSL_CTX */
    if ((ret = wolfSSL_CTX_use_PrivateKey_file(ctx, KEY_FILE, WOLFSSL_FILETYPE_PEM))
        != WOLFSSL_SUCCESS) {
        fprintf(stderr, "ERROR: failed to load %s, please check the file.\n",
                KEY_FILE);
        goto exit;
    }

    /* Load CA certificate into WOLFSSL_CTX */
    if ((ret = wolfSSL_CTX_load_verify_locations(ctx, CA_FILE, NULL))
         != WOLFSSL_SUCCESS) {
        fprintf(stderr, "ERROR: failed to load %s, please check the file.\n",
                CA_FILE);
        goto exit;
    }

    /* Create a WOLFSSL object */
    if ((ssl = wolfSSL_new(ctx)) == NULL) {
        fprintf(stderr, "ERROR: failed to create WOLFSSL object\n");
        ret = -1; goto exit;
    }

    /* Attach wolfSSL to the socket */
    if ((ret = wolfSSL_set_fd(ssl, sockfd)) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "ERROR: Failed to set the file descriptor\n");
        goto exit;
    }

    /* Connect to wolfSSL on the server side */
#ifdef WOLFSSL_ASYNC_CRYPT
    err = 0; /* Reset error */
#endif
    do {
    #ifdef WOLFSSL_ASYNC_CRYPT
        if (err == WC_PENDING_E) {
            ret = wolfSSL_AsyncPoll(ssl, WOLF_POLL_FLAG_CHECK_HW);
            if (ret < 0) { break; } else if (ret == 0) { continue; }
        }
    #endif
        ret = wolfSSL_connect(ssl);
        err = wolfSSL_get_error(ssl, 0);
    } while (err == WC_PENDING_E);
    if (ret != WOLFSSL_SUCCESS) {
        fprintf(stderr, "wolfSSL_connect error %d: %s\n",
                err, wolfSSL_ERR_error_string(err, errBuff));
        goto exit;
    }

    /* Get a message for the server from stdin */
    printf("Message for server: ");
    memset(buff, 0, sizeof(buff));
    if (fgets(buff, sizeof(buff), stdin) == NULL) {
        fprintf(stderr, "ERROR: failed to get message for server\n");
        ret = -1; goto exit;
    }
    len = strnlen(buff, sizeof(buff));

    /* Send the message to the server */
    if ((ret = wolfSSL_write(ssl, buff, len)) != len) {
        fprintf(stderr, "ERROR: failed to write entire message\n");
        fprintf(stderr, "%d bytes of %d bytes were sent", ret, (int) len);
        goto exit;
    }

    /* Read the server data into our buff array */
    memset(buff, 0, sizeof(buff));
    if ((ret = wolfSSL_read(ssl, buff, sizeof(buff)-1)) < 0) {
        fprintf(stderr, "ERROR: failed to read\n");
        goto exit;
    }

    /* Print to stdout any data the server sends */
    printf("Server: %s\n", buff);

    /* Return reporting a success */
    ret = 0;

exit:
    /* Cleanup and return */
    if (sockfd != SOCKET_INVALID)
        close(sockfd);          /* Close the connection to the server       */
    if (ssl)
        wolfSSL_free(ssl);      /* Free the wolfSSL object                  */
    if (ctx)
        wolfSSL_CTX_free(ctx);  /* Free the wolfSSL context object          */
    wolfSSL_Cleanup();          /* Cleanup the wolfSSL environment          */

    (void)argc;
    (void)argv;

    return ret;
}
