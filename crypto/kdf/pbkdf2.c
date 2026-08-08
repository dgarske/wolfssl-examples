/* pbkdf2.c
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

/* Example of PBKDF2 (RFC 2898) password-based key derivation, run against the
 * PBKDF2-HMAC-SHA256 test vector from RFC 7914 Section 11, then with
 * realistic parameters. */

#include <stdio.h>
#include <string.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/pwdbased.h>
#include <wolfssl/wolfcrypt/random.h>

#ifndef NO_PWDBASED

/* RFC 7914 Section 11: PBKDF2-HMAC-SHA256, P="passwd", S="salt", c=1,
 * dkLen=64. */
static const byte expected_dk[64] = {
    0x55, 0xac, 0x04, 0x6e, 0x56, 0xe3, 0x08, 0x9f,
    0xec, 0x16, 0x91, 0xc2, 0x25, 0x44, 0xb6, 0x05,
    0xf9, 0x41, 0x85, 0x21, 0x6d, 0xde, 0x04, 0x65,
    0xe6, 0x8b, 0x9d, 0x57, 0xc2, 0x0d, 0xac, 0xbc,
    0x49, 0xca, 0x9c, 0xcc, 0xf1, 0x79, 0xb6, 0x45,
    0x99, 0x16, 0x64, 0xb3, 0x9d, 0x77, 0xef, 0x31,
    0x7c, 0x71, 0xb8, 0x45, 0xb1, 0xe3, 0x0b, 0xd5,
    0x09, 0x11, 0x20, 0x41, 0xd3, 0xa1, 0x97, 0x83
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
    int    ret;
    byte   dk[64];
    WC_RNG rng;
    byte   salt[16];
    const char* password = "correct horse battery staple";

    /* Known-answer check. */
    ret = wc_PBKDF2(dk, (const byte*)"passwd", 6, (const byte*)"salt", 4, 1,
                    (int)sizeof(dk), WC_SHA256);
    if (ret != 0) {
        printf("wc_PBKDF2 failed %d\n", ret);
        return 1;
    }
    if (memcmp(dk, expected_dk, sizeof(dk)) != 0) {
        printf("Derived key does not match RFC 7914 test vector!\n");
        return 1;
    }
    printf("Derived key matches RFC 7914 test vector\n");

    /* Realistic use: random per-user salt and a high iteration count. The
     * iteration count is the work factor; NIST SP 800-132 requires at least
     * 1000, modern guidance is 600000+ for SHA-256. */
    ret = wc_InitRng(&rng);
    if (ret != 0) {
        printf("wc_InitRng failed %d\n", ret);
        return 1;
    }
    ret = wc_RNG_GenerateBlock(&rng, salt, sizeof(salt));
    wc_FreeRng(&rng);
    if (ret != 0) {
        printf("wc_RNG_GenerateBlock failed %d\n", ret);
        return 1;
    }

    ret = wc_PBKDF2(dk, (const byte*)password, (int)strlen(password), salt,
                    (int)sizeof(salt), 600000, 32, WC_SHA256);
    if (ret != 0) {
        printf("wc_PBKDF2 failed %d\n", ret);
        return 1;
    }
    print_hex("salt", salt, sizeof(salt));
    print_hex("key ", dk, 32);
    printf("Derived 32-byte key with 600000 iterations\n");

    return 0;
}

#else

int main(void)
{
    printf("Please build wolfSSL without NO_PWDBASED (PBKDF2 is on by "
           "default)\n");
    return 0;
}

#endif /* !NO_PWDBASED */
