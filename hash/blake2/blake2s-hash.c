/* blake2s-hash.c
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

/* Example of incremental BLAKE2s hashing with the wc_Blake2s API. */

#include <stdio.h>
#include <string.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/blake2.h>

#ifdef HAVE_BLAKE2S

#define DIGEST_SZ 32

/* BLAKE2s-256("abc") from RFC 7693 Appendix B. */
static const byte kat_abc[DIGEST_SZ] = {
    0x50, 0x8c, 0x5e, 0x8c, 0x32, 0x7c, 0x14, 0xe2,
    0xe1, 0xa7, 0x2b, 0xa3, 0x4e, 0xeb, 0x45, 0x2f,
    0x37, 0x45, 0x8b, 0x20, 0x9e, 0xd6, 0x3a, 0x29,
    0x4d, 0x99, 0x9b, 0x4c, 0x86, 0x67, 0x59, 0x82
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
    Blake2s b2s;
    byte    digest[DIGEST_SZ];
    const char* msg = (argc > 1) ? argv[1] : "abc";

    ret = wc_InitBlake2s(&b2s, DIGEST_SZ);
    if (ret != 0) {
        printf("wc_InitBlake2s failed %d\n", ret);
        return 1;
    }

    ret = wc_Blake2sUpdate(&b2s, (const byte*)msg, (word32)strlen(msg));
    if (ret != 0) {
        printf("wc_Blake2sUpdate failed %d\n", ret);
        return 1;
    }

    ret = wc_Blake2sFinal(&b2s, digest, DIGEST_SZ);
    if (ret != 0) {
        printf("wc_Blake2sFinal failed %d\n", ret);
        return 1;
    }

    print_hex("BLAKE2s-256", digest, DIGEST_SZ);

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
    printf("Please build wolfSSL with ./configure --enable-blake2s\n");
    return 0;
}

#endif /* HAVE_BLAKE2S */
