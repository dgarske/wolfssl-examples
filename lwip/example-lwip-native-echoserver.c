/* example-lwip-native-echoserver.c
 *
 * Copyright (C) 2006-2022 wolfSSL Inc.
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

/* 
gcc -o example-lwip-native-echoclient.c -I lwip-src/src/include example-lwip-native-echoclient.c -lwolfssl
*/

#include "lwip/debug.h"
#include "lwip/stats.h"
#include "lwip/tcp.h"
#include "lwip/memp.h"
#include <stdio.h>
#include <string.h>

#ifndef WOLFSSL_USER_SETTINGS
#include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>

#ifndef NO_RSA
    #define USE_CERT_BUFFERS_2048
    #define SERVER_CERT        server_cert_der_2048
    #define SERVER_CERT_LEN    sizeof_server_cert_der_2048
    #define SERVER_KEY         server_key_der_2048
    #define SERVER_KEY_LEN     sizeof_server_key_der_2048
#elif defined(HAVE_ECC)
    #define USE_CERT_BUFFERS_256
    #define SERVER_CERT        serv_ecc_der_256
    #define SERVER_CERT_LEN    sizeof_serv_ecc_der_256
    #define SERVER_KEY         ecc_key_der_256
    #define SERVER_KEY_LEN     sizeof_ecc_key_der_256
#endif

#include <wolfssl/certs_test.h>
#include <wolfcrypt/test/test.h>


static err_t tcp_echoserver_connected(void *arg, struct tcp_pcb *tpcb, err_t err);
static void TLS_shutdown(void);
static int TLS_accept(void);
static int TLS_setup(void);

struct tcp_pcb *tls_pcb   = NULL;
struct tcp_pcb *debug_pcb = NULL;

static int tlsConnected = 0;
static int tcpConnected = 0;
static int tlsWaitingForReply = 0;

static WOLFSSL_CTX *ctx = NULL;
static WOLFSSL *ssl = NULL;

void loggingCb(const int logLevel, const char *const logMessage)
{
    printf("%s\n", logMessage);
    (void)logLevel;
}

void tls_echoserver_accept(void)
{
    ip_addr_t DestIPaddr;

    if (tcpConnected == 0) {
        tls_pcb = tcp_new();
        if (tls_pcb != NULL) {
            IP4_ADDR( &DestIPaddr, DEST_IP_ADDR0, DEST_IP_ADDR1, DEST_IP_ADDR2, DEST_IP_ADDR3 );
            tcp_connect(tls_pcb,&DestIPaddr,DEST_PORT,tcp_echoserver_connected);
        }
    }

    if (tcpConnected == 1 && tlsConnected == 0) {
        TLS_accept();
    }

    if (tlsConnected == 1) {
        int ret;
        char reply[256];
        int err;

        if (tlsWaitingForReply == 0) {
            ret = wolfSSL_write(ssl, "TLS **TEST 1** ", sizeof("TLS **TEST 1** "));
            if (ret <= 0) {
                loggingCb(0, "error when writing TLS message");
                TLS_shutdown();
            }
            else {
                tlsWaitingForReply = 1;
            }
        }

        /* read a reply from the client */
        if (tlsWaitingForReply == 1) {
            memset(reply, 0, sizeof(reply));
            ret = wolfSSL_read(ssl, reply, sizeof(reply));
            if (ret <= 0) {
                err = wolfSSL_get_error(ssl, 0);
                if (err != SSL_ERROR_WANT_READ &&
                    err != WOLFSSL_ERROR_WANT_WRITE) {
                    loggingCb(0, "error when reading TLS message");
                    TLS_shutdown();
                }
            }
            if (ret > 0) {
                loggingCb(0, reply);
                TLS_shutdown(); /* received reply, done with connection */
            }
        }
    }
}


static err_t tcp_echoserver_connected(void *arg, struct tcp_pcb *tpcb, err_t err)
{
    if (err == ERR_OK) {
        tcpConnected = 1;
        /* a tcp_poll could be added here for connection timeout checking */
        return TLS_setup();
    }
    return ERR_OK;
}


/* setup all the TLS structures and load CA */
static int TLS_setup(void)
{
    int ret;

#ifdef DEBUG_WOLFSSL
    /* redirect wolfssl debug print outs */
    wolfSSL_SetLoggingCb(loggingCb);
    wolfSSL_Debugging_ON();
#endif
    wolfSSL_Init(); /* called once on program startup */
    ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method());
    if (ctx == NULL) {
        loggingCb(0, "ctx was null");
        TLS_shutdown();
        return ERR_MEM;
    }

    /* Load server certificate into WOLFSSL_CTX */
    ret = wolfSSL_CTX_use_certificate_buffer(server_ctx, SERVER_CERT,
            SERVER_CERT_LEN, WOLFSSL_FILETYPE_ASN1);
    if (ret != WOLFSSL_SUCCESS) {
        loggingCb(0, "ERROR: failed to load server certificate");
        ret = -1;
    }

    /* Load server key into WOLFSSL_CTX */
    if (wolfSSL_CTX_use_PrivateKey_buffer(server_ctx,
            SERVER_KEY, SERVER_KEY_LEN, WOLFSSL_FILETYPE_ASN1) !=
            WOLFSSL_SUCCESS) {
        loggingCb(0, "ERROR: failed to load server key");
        ret = -1;
    }

    ret = wolfSSL_CTX_load_verify_buffer(ctx, ca_ecc_cert_der_256,
        sizeof(ca_ecc_cert_der_256), WOLFSSL_FILETYPE_ASN1);
    if (ret != WOLFSSL_SUCCESS) {
        loggingCb(0, "error loading in verify buffer");
        return ERR_MEM;
    }

    ssl = wolfSSL_new(ctx);
    if (ssl == NULL) {
        loggingCb(0, "ssl was null");
        return ERR_MEM;
    }
    wolfSSL_SetIO_LwIP(ssl, tls_pcb, NULL, NULL, NULL);
    return ERR_OK;
}

static int TLS_accept(void)
{
    if (wolfSSL_accept(ssl) != WOLFSSL_SUCCESS) {
        /* check if hitting a want read/write case and should call again */
        int err = wolfSSL_get_error(ssl, 0);
        if (err != SSL_ERROR_WANT_READ && err != WOLFSSL_ERROR_WANT_WRITE) {
            loggingCb(0, "connect error, shutting down");
            loggingCb(0, wolfSSL_ERR_reason_error_string(err));
            TLS_shutdown();
            return ERR_CONN;
        }
        loggingCb(0, "found want read/write");
    }
    else {
        loggingCb(0, "setting tlsConnected to 1");
        tlsConnected = 1;
    }
    return ERR_OK;
}

/* close all connections and free TLS session */
static void TLS_shutdown(void)
{
    if (ssl != NULL) {
        wolfSSL_shutdown(ssl);
        wolfSSL_free(ssl);
    }

    if (ctx != NULL) {
        wolfSSL_CTX_free(ctx);
    }

    tlsConnected = 0;
    tlsWaitingForReply = 0;
    wolfSSL_Cleanup();

    if (tcpConnected == 1) {
        tcp_output(tls_pcb);
        tcp_close(tls_pcb);
        tls_pcb = NULL;
        tcpConnected = 0;
    }
}
