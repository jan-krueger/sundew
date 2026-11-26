/*
 * Copyright (C) The Sundew Authors
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * SipHash-1-3.
 */

#ifndef SW_SIPHASH_H
#define SW_SIPHASH_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>


#define SW_ROTL(x, b)  (uint64_t) (((x) << (b)) | ((x) >> (64 - (b))))

#define SW_SIPROUND                                                         \
    do {                                                                    \
        v0 += v1; v1 = SW_ROTL(v1, 13); v1 ^= v0; v0 = SW_ROTL(v0, 32);     \
        v2 += v3; v3 = SW_ROTL(v3, 16); v3 ^= v2;                           \
        v0 += v3; v3 = SW_ROTL(v3, 21); v3 ^= v0;                           \
        v2 += v1; v1 = SW_ROTL(v1, 17); v1 ^= v2; v2 = SW_ROTL(v2, 32);     \
    } while (0)


static inline uint64_t
sw_siphash13(const uint64_t key[2], const unsigned char *in, size_t len)
{
    size_t    i, left;
    uint64_t  v0, v1, v2, v3, m, b;

    v0 = 0x736f6d6570736575ULL ^ key[0];
    v1 = 0x646f72616e646f6dULL ^ key[1];
    v2 = 0x6c7967656e657261ULL ^ key[0];
    v3 = 0x7465646279746573ULL ^ key[1];

    b = (uint64_t) len << 56;
    left = len & 7;

    for (i = 0; i + 8 <= len; i += 8) {
        memcpy(&m, in + i, 8);
        v3 ^= m;
        SW_SIPROUND;
        v0 ^= m;
    }

    switch (left) {
    case 7: b |= (uint64_t) in[i + 6] << 48; /* fall through */
    case 6: b |= (uint64_t) in[i + 5] << 40; /* fall through */
    case 5: b |= (uint64_t) in[i + 4] << 32; /* fall through */
    case 4: b |= (uint64_t) in[i + 3] << 24; /* fall through */
    case 3: b |= (uint64_t) in[i + 2] << 16; /* fall through */
    case 2: b |= (uint64_t) in[i + 1] << 8;  /* fall through */
    case 1: b |= (uint64_t) in[i];           /* fall through */
    case 0: break;
    }

    v3 ^= b;
    SW_SIPROUND;
    v0 ^= b;

    v2 ^= 0xff;
    SW_SIPROUND;
    SW_SIPROUND;
    SW_SIPROUND;

    return v0 ^ v1 ^ v2 ^ v3;
}

#endif /* SW_SIPHASH_H */
