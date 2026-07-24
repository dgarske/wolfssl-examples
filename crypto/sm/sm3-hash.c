/* sm3-hash.c
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

/* Example of incremental SM3 hashing (GB/T 32905-2016), checked against the
 * standard's "abc" test vector. */

#include <stdio.h>
#include <string.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/sm3.h>

#ifdef WOLFSSL_SM3

/* SM3("abc") from GB/T 32905-2016 Appendix A. */
static const byte kat_abc[WC_SM3_DIGEST_SIZE] = {
    0x66, 0xc7, 0xf0, 0xf4, 0x62, 0xee, 0xed, 0xd9,
    0xd1, 0xf2, 0xd4, 0x6b, 0xdc, 0x10, 0xe4, 0xe2,
    0x41, 0x67, 0xc4, 0x87, 0x5c, 0xf2, 0xf7, 0xa2,
    0x29, 0x7d, 0xa0, 0x2b, 0x8f, 0x4b, 0xa8, 0xe0
};

static void print_hex(const char* label, const byte* data, word32 len)
{
    word32 i;

    printf("%s: ", label);
    for (i = 0; i < len; i++)
        printf("%02x", data[i]);
    printf("\n");
}

int main(int argc, char* argv[])
{
    int    ret;
    wc_Sm3 sm3;
    byte   digest[WC_SM3_DIGEST_SIZE];
    const char* msg = (argc > 1) ? argv[1] : "abc";

    ret = wc_InitSm3(&sm3, NULL, INVALID_DEVID);
    if (ret != 0) {
        printf("wc_InitSm3 failed %d\n", ret);
        return 1;
    }

    /* Data may be added in as many update calls as needed. */
    ret = wc_Sm3Update(&sm3, (const byte*)msg, (word32)strlen(msg));
    if (ret == 0)
        ret = wc_Sm3Final(&sm3, digest);
    wc_Sm3Free(&sm3);
    if (ret != 0) {
        printf("SM3 hash failed %d\n", ret);
        return 1;
    }

    print_hex("SM3", digest, WC_SM3_DIGEST_SIZE);

    if (argc <= 1) {
        if (memcmp(digest, kat_abc, WC_SM3_DIGEST_SIZE) != 0) {
            printf("Digest does not match GB/T 32905 test vector!\n");
            return 1;
        }
        printf("Digest matches GB/T 32905 test vector\n");
    }

    return 0;
}

#else

int main(void)
{
    printf("Please install the wolfsm overlay and build wolfSSL with "
           "./configure --enable-sm3\n");
    return 0;
}

#endif /* WOLFSSL_SM3 */
