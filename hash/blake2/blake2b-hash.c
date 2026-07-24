/* blake2b-hash.c
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

/* Example of incremental BLAKE2b hashing with the wc_Blake2b API. */

#include <stdio.h>
#include <string.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/blake2.h>

#ifdef HAVE_BLAKE2B

#define DIGEST_SZ 64

/* BLAKE2b-512("abc") from RFC 7693 Appendix A. */
static const byte kat_abc[DIGEST_SZ] = {
    0xba, 0x80, 0xa5, 0x3f, 0x98, 0x1c, 0x4d, 0x0d,
    0x6a, 0x27, 0x97, 0xb6, 0x9f, 0x12, 0xf6, 0xe9,
    0x4c, 0x21, 0x2f, 0x14, 0x68, 0x5a, 0xc4, 0xb7,
    0x4b, 0x12, 0xbb, 0x6f, 0xdb, 0xff, 0xa2, 0xd1,
    0x7d, 0x87, 0xc5, 0x39, 0x2a, 0xab, 0x79, 0x2d,
    0xc2, 0x52, 0xd5, 0xde, 0x45, 0x33, 0xcc, 0x95,
    0x18, 0xd3, 0x8a, 0xa8, 0xdb, 0xf1, 0x92, 0x5a,
    0xb9, 0x23, 0x86, 0xed, 0xd4, 0x00, 0x99, 0x23
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
    int     ret;
    Blake2b b2b;
    byte    digest[DIGEST_SZ];
    const char* msg = (argc > 1) ? argv[1] : "abc";

    ret = wc_InitBlake2b(&b2b, DIGEST_SZ);
    if (ret != 0) {
        printf("wc_InitBlake2b failed %d\n", ret);
        return 1;
    }

    /* Data may be added in as many update calls as needed. */
    ret = wc_Blake2bUpdate(&b2b, (const byte*)msg, (word32)strlen(msg));
    if (ret != 0) {
        printf("wc_Blake2bUpdate failed %d\n", ret);
        return 1;
    }

    ret = wc_Blake2bFinal(&b2b, digest, DIGEST_SZ);
    if (ret != 0) {
        printf("wc_Blake2bFinal failed %d\n", ret);
        return 1;
    }

    print_hex("BLAKE2b-512", digest, DIGEST_SZ);

    if (argc <= 1) {
        if (memcmp(digest, kat_abc, DIGEST_SZ) != 0) {
            printf("Digest does not match RFC 7693 test vector!\n");
            return 1;
        }
        printf("Digest matches RFC 7693 test vector\n");
    }

    return 0;
}

#else

int main(void)
{
    printf("Please build wolfSSL with ./configure --enable-blake2\n");
    return 0;
}

#endif /* HAVE_BLAKE2B */
