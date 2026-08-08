/* hkdf.c
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

/* Example of HKDF (RFC 5869): extract-then-expand key derivation, run against
 * RFC 5869 Test Case 1. */

#include <stdio.h>
#include <string.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/hmac.h>

#ifdef HAVE_HKDF

/* RFC 5869 Test Case 1 (SHA-256). */
static const byte ikm[22] = {
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b
};
static const byte salt[13] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c
};
static const byte info[10] = {
    0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
    0xf8, 0xf9
};
static const byte expected_prk[32] = {
    0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf,
    0x0d, 0xdc, 0x3f, 0x0d, 0xc4, 0x7b, 0xba, 0x63,
    0x90, 0xb6, 0xc7, 0x3b, 0xb5, 0x0f, 0x9c, 0x31,
    0x22, 0xec, 0x84, 0x4a, 0xd7, 0xc2, 0xb3, 0xe5
};
static const byte expected_okm[42] = {
    0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a,
    0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f, 0x2a,
    0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c,
    0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4, 0xc5, 0xbf,
    0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18,
    0x58, 0x65
};

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
    int  ret;
    byte prk[32];
    byte okm[42];

    /* Extract: concentrate the input keying material into a fixed-size PRK. */
    ret = wc_HKDF_Extract(WC_SHA256, salt, sizeof(salt), ikm, sizeof(ikm),
                          prk);
    if (ret != 0) {
        printf("wc_HKDF_Extract failed %d\n", ret);
        return 1;
    }
    print_hex("PRK", prk, sizeof(prk));
    if (memcmp(prk, expected_prk, sizeof(prk)) != 0) {
        printf("PRK does not match RFC 5869 test vector!\n");
        return 1;
    }

    /* Expand: stretch the PRK into the output keying material. */
    ret = wc_HKDF_Expand(WC_SHA256, prk, sizeof(prk), info, sizeof(info),
                         okm, sizeof(okm));
    if (ret != 0) {
        printf("wc_HKDF_Expand failed %d\n", ret);
        return 1;
    }
    print_hex("OKM", okm, sizeof(okm));
    if (memcmp(okm, expected_okm, sizeof(okm)) != 0) {
        printf("OKM does not match RFC 5869 test vector!\n");
        return 1;
    }

    /* wc_HKDF does both steps in one call. */
    memset(okm, 0, sizeof(okm));
    ret = wc_HKDF(WC_SHA256, ikm, sizeof(ikm), salt, sizeof(salt), info,
                  sizeof(info), okm, sizeof(okm));
    if (ret != 0) {
        printf("wc_HKDF failed %d\n", ret);
        return 1;
    }
    if (memcmp(okm, expected_okm, sizeof(okm)) != 0) {
        printf("One-shot OKM does not match!\n");
        return 1;
    }
    printf("HKDF output matches RFC 5869 Test Case 1\n");

    return 0;
}

#else

int main(void)
{
    printf("Please build wolfSSL with ./configure --enable-hkdf\n");
    return 0;
}

#endif /* HAVE_HKDF */
