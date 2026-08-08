/* siphash-mac.c
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

/* Example of SipHash-2-4 as a short-output keyed MAC.
 *
 * SipHash is designed for short inputs (hash table keys, network packet
 * authentication) where a fast 64- or 128-bit keyed MAC is enough. */

#include <stdio.h>
#include <string.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/siphash.h>

#ifdef WOLFSSL_SIPHASH

/* Reference test vector from https://github.com/veorq/SipHash: key 00..0f,
 * message 00..0e, 8-byte output. */
static const byte kat_key[SIPHASH_KEY_SIZE] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};
static const byte kat_msg[15] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e
};
static const byte kat_mac[SIPHASH_MAC_SIZE_8] = {
    0xe5, 0x45, 0xbe, 0x49, 0x61, 0xca, 0x29, 0xa1
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
    int     ret;
    SipHash sipHash;
    byte    mac8[SIPHASH_MAC_SIZE_8];
    byte    mac16[SIPHASH_MAC_SIZE_16];

    /* One-shot with an 8-byte tag, checked against the reference vector. */
    ret = wc_SipHash(kat_key, kat_msg, sizeof(kat_msg), mac8,
                     SIPHASH_MAC_SIZE_8);
    if (ret != 0) {
        printf("wc_SipHash failed %d\n", ret);
        return 1;
    }
    print_hex("SipHash-2-4 64-bit ", mac8, sizeof(mac8));
    if (memcmp(mac8, kat_mac, sizeof(kat_mac)) != 0) {
        printf("MAC does not match reference test vector!\n");
        return 1;
    }
    printf("MAC matches reference test vector\n");

    /* One-shot with a 16-byte tag. */
    ret = wc_SipHash(kat_key, kat_msg, sizeof(kat_msg), mac16,
                     SIPHASH_MAC_SIZE_16);
    if (ret != 0) {
        printf("wc_SipHash failed %d\n", ret);
        return 1;
    }
    print_hex("SipHash-2-4 128-bit", mac16, sizeof(mac16));

    /* Incremental API produces the same tag as one-shot. */
    ret = wc_InitSipHash(&sipHash, kat_key, SIPHASH_MAC_SIZE_8);
    if (ret == 0)
        ret = wc_SipHashUpdate(&sipHash, kat_msg, 8);
    if (ret == 0)
        ret = wc_SipHashUpdate(&sipHash, kat_msg + 8, sizeof(kat_msg) - 8);
    if (ret == 0)
        ret = wc_SipHashFinal(&sipHash, mac8, SIPHASH_MAC_SIZE_8);
    if (ret != 0) {
        printf("incremental SipHash failed %d\n", ret);
        return 1;
    }
    if (memcmp(mac8, kat_mac, sizeof(kat_mac)) != 0) {
        printf("Incremental MAC does not match one-shot MAC!\n");
        return 1;
    }
    printf("Incremental MAC matches one-shot MAC\n");

    return 0;
}

#else

int main(void)
{
    printf("Please build wolfSSL with ./configure --enable-siphash\n");
    return 0;
}

#endif /* WOLFSSL_SIPHASH */
