/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */
/* Header file for crc32.c - see copyright/license information in that file */

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

extern uint32_t crc32c(uint32_t crc, const uint8_t *buf, size_t len);

/* Apply the zeros operator table to crc. */
extern const uint32_t crc32c_4k[4][256];
extern const uint32_t crc32c_1M[4][256];
extern const uint32_t crc32c_1G[4][256];
extern const uint32_t crc32c_1T[4][256];
static inline uint32_t crc32c_shift(const uint32_t zeros[][256], uint32_t crc)
{
    return zeros[0][crc & 0xff] ^ zeros[1][(crc >> 8) & 0xff] ^
        zeros[2][(crc >> 16) & 0xff] ^ zeros[3][crc >> 24];
}

#ifdef __cplusplus
}
#endif