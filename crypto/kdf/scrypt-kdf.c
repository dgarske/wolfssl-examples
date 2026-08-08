/* scrypt-kdf.c
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

/* Example of scrypt (RFC 7914) memory-hard password-based key derivation,
 * run against the test vector from RFC 7914 Section 12. */

#include <stdio.h>
#include <string.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/pwdbased.h>

#ifdef HAVE_SCRYPT

/* RFC 7914 Section 12, vector 2: P="password", S="NaCl", N=1024, r=8, p=16,
 * dkLen=64. */
static const byte expected_dk[64] = {
    0xfd, 0xba, 0xbe, 0x1c, 0x9d, 0x34, 0x72, 0x00,
    0x78, 0x56, 0xe7, 0x19, 0x0d, 0x01, 0xe9, 0xfe,
    0x7c, 0x6a, 0xd7, 0xcb, 0xc8, 0x23, 0x78, 0x30,
    0xe7, 0x73, 0x76, 0x63, 0x4b, 0x37, 0x31, 0x62,
    0x2e, 0xaf, 0x30, 0xd9, 0x2e, 0x22, 0xa3, 0x88,
    0x6f, 0xf1, 0x09, 0x27, 0x9d, 0x98, 0x30, 0xda,
    0xc7, 0x27, 0xaf, 0xb9, 0x4a, 0x83, 0xee, 0x6d,
    0x83, 0x60, 0xcb, 0xdf, 0xa2, 0xcc, 0x06, 0x40
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
    byte dk[64];

    /* cost is log2(N): 10 -> N=1024. r (block size) scales memory use,
     * p (parallelization) scales CPU cost. */
    ret = wc_scrypt(dk, (const byte*)"password", 8, (const byte*)"NaCl", 4,
                    10, 8, 16, (int)sizeof(dk));
    if (ret != 0) {
        printf("wc_scrypt failed %d\n", ret);
        return 1;
    }
    print_hex("key", dk, sizeof(dk));

    if (memcmp(dk, expected_dk, sizeof(dk)) != 0) {
        printf("Derived key does not match RFC 7914 test vector!\n");
        return 1;
    }
    printf("Derived key matches RFC 7914 test vector\n");

    return 0;
}

#else

int main(void)
{
    printf("Please build wolfSSL with ./configure --enable-scrypt\n");
    return 0;
}

#endif /* HAVE_SCRYPT */
