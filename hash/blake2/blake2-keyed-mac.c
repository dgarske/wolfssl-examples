/* blake2-keyed-mac.c
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

/* Example of BLAKE2b in keyed mode, used as a MAC.
 *
 * BLAKE2's native keyed mode replaces the HMAC construction: the key is mixed
 * into the initial state, so a single hash pass produces the tag. */

#include <stdio.h>
#include <string.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/blake2.h>
#include <wolfssl/wolfcrypt/random.h>

#ifdef HAVE_BLAKE2B

/* 32-byte tag is plenty for a MAC; BLAKE2b allows 1-64. */
#define TAG_SZ 32
#define KEY_SZ 32

static void print_hex(const char* label, const byte* data, word32 len)
{
    word32 i;

    printf("%s: ", label);
    for (i = 0; i < len; i++)
        printf("%02x", data[i]);
    printf("\n");
}

static int mac_message(const byte* key, word32 keySz, const char* msg,
                       byte* tag, word32 tagSz)
{
    int     ret;
    Blake2b b2b;

    ret = wc_InitBlake2b_WithKey(&b2b, tagSz, key, keySz);
    if (ret == 0)
        ret = wc_Blake2bUpdate(&b2b, (const byte*)msg, (word32)strlen(msg));
    if (ret == 0)
        ret = wc_Blake2bFinal(&b2b, tag, tagSz);

    return ret;
}

int main(void)
{
    int    ret;
    WC_RNG rng;
    byte   key[KEY_SZ];
    byte   tag[TAG_SZ];
    byte   check[TAG_SZ];
    const char* msg = "authenticate this message";

    ret = wc_InitRng(&rng);
    if (ret != 0) {
        printf("wc_InitRng failed %d\n", ret);
        return 1;
    }

    ret = wc_RNG_GenerateBlock(&rng, key, KEY_SZ);
    wc_FreeRng(&rng);
    if (ret != 0) {
        printf("wc_RNG_GenerateBlock failed %d\n", ret);
        return 1;
    }

    ret = mac_message(key, KEY_SZ, msg, tag, TAG_SZ);
    if (ret != 0) {
        printf("MAC generation failed %d\n", ret);
        return 1;
    }
    print_hex("key", key, KEY_SZ);
    print_hex("tag", tag, TAG_SZ);

    /* Verifier recomputes the tag with the shared key and compares. */
    ret = mac_message(key, KEY_SZ, msg, check, TAG_SZ);
    if (ret != 0) {
        printf("MAC verification failed %d\n", ret);
        return 1;
    }
    if (memcmp(tag, check, TAG_SZ) != 0) {
        printf("MAC mismatch!\n");
        return 1;
    }
    printf("MAC verified\n");

    /* A different key must produce a different tag. */
    key[0] ^= 0x01;
    ret = mac_message(key, KEY_SZ, msg, check, TAG_SZ);
    if (ret != 0) {
        printf("MAC computation failed %d\n", ret);
        return 1;
    }
    if (memcmp(tag, check, TAG_SZ) == 0) {
        printf("Tag did not change with key!\n");
        return 1;
    }
    printf("Wrong key rejected\n");

    return 0;
}

#else

int main(void)
{
    printf("Please build wolfSSL with ./configure --enable-blake2\n");
    return 0;
}

#endif /* HAVE_BLAKE2B */
