/*
   BLAKE2 reference source code package - reference C implementations

   Copyright 2012, Samuel Neves <sneves@dei.uc.pt>.  You may use this under the
   terms of the CC0, the OpenSSL Licence, or the Apache Public License 2.0, at
   your option.  The terms of these licenses can be found at:

   - CC0 1.0 Universal : http://creativecommons.org/publicdomain/zero/1.0
   - OpenSSL license   : https://www.openssl.org/source/license.html
   - Apache 2.0        : http://www.apache.org/licenses/LICENSE-2.0

   More information about the BLAKE2 hash function can be found at
   https://blake2.net.
*/

#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <arm_neon.h>

#include "blake2.h"
#include "blake2-impl.h"

static const uint64_t blake2b_IV[8] =
{
  0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
  0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
  0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
  0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
};

/*
static const uint8_t blake2b_sigma[12][16] =
{
  {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 } ,
  { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 } ,
  { 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 } ,
  {  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 } ,
  {  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 } ,
  {  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 } ,
  { 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 } ,
  { 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 } ,
  {  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 } ,
  { 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13 , 0 } ,
  {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 } ,
  { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 }
};
*/

static void blake2b_set_lastnode( blake2b_state *S )
{
  S->f[1] = (uint64_t)-1;
}

/* Some helper functions, not necessarily useful */
static int blake2b_is_lastblock( const blake2b_state *S )
{
  return S->f[0] != 0;
}

static void blake2b_set_lastblock( blake2b_state *S )
{
  if( S->last_node ) blake2b_set_lastnode( S );

  S->f[0] = (uint64_t)-1;
}

static void blake2b_increment_counter( blake2b_state *S, const uint64_t inc )
{
  S->t[0] += inc;
  S->t[1] += ( S->t[0] < inc );
}

static void blake2b_init0( blake2b_state *S )
{
  size_t i;
  memset( S, 0, sizeof( blake2b_state ) );

  for( i = 0; i < 8; ++i ) S->h[i] = blake2b_IV[i];
}

/* init xors IV with input parameter block */
int blake2b_init_param( blake2b_state *S, const blake2b_param *P )
{
  const uint8_t *p = ( const uint8_t * )( P );
  size_t i;

  blake2b_init0( S );

  /* IV XOR ParamBlock */
  for( i = 0; i < 8; ++i )
    S->h[i] ^= load64( p + sizeof( S->h[i] ) * i );

  S->outlen = P->digest_length;
  return 0;
}



int blake2b_init( blake2b_state *S, size_t outlen )
{
  blake2b_param P[1];

  if ( ( !outlen ) || ( outlen > BLAKE2B_OUTBYTES ) ) return -1;

  P->digest_length = (uint8_t)outlen;
  P->key_length    = 0;
  P->fanout        = 1;
  P->depth         = 1;
  store32( &P->leaf_length, 0 );
  store32( &P->node_offset, 0 );
  store32( &P->xof_length, 0 );
  P->node_depth    = 0;
  P->inner_length  = 0;
  memset( P->reserved, 0, sizeof( P->reserved ) );
  memset( P->salt,     0, sizeof( P->salt ) );
  memset( P->personal, 0, sizeof( P->personal ) );
  return blake2b_init_param( S, P );
}


int blake2b_init_key( blake2b_state *S, size_t outlen, const void *key, size_t keylen )
{
  blake2b_param P[1];

  if ( ( !outlen ) || ( outlen > BLAKE2B_OUTBYTES ) ) return -1;

  if ( !key || !keylen || keylen > BLAKE2B_KEYBYTES ) return -1;

  P->digest_length = (uint8_t)outlen;
  P->key_length    = (uint8_t)keylen;
  P->fanout        = 1;
  P->depth         = 1;
  store32( &P->leaf_length, 0 );
  store32( &P->node_offset, 0 );
  store32( &P->xof_length, 0 );
  P->node_depth    = 0;
  P->inner_length  = 0;
  memset( P->reserved, 0, sizeof( P->reserved ) );
  memset( P->salt,     0, sizeof( P->salt ) );
  memset( P->personal, 0, sizeof( P->personal ) );

  if( blake2b_init_param( S, P ) < 0 ) return -1;

  {
    uint8_t block[BLAKE2B_BLOCKBYTES];
    memset( block, 0, BLAKE2B_BLOCKBYTES );
    memcpy( block, key, keylen );
    blake2b_update( S, block, BLAKE2B_BLOCKBYTES );
    secure_zero_memory( block, BLAKE2B_BLOCKBYTES ); /* Burn the key from stack */
  }
  return 0;
}

#undef LOAD_MSG_0_1
#define LOAD_MSG_0_1(b0, b1) \
do { b0 = vcombine_u64(vget_low_u64(m0), vget_low_u64(m1)); b1 = vcombine_u64(vget_low_u64(m2), vget_low_u64(m3)); } while(0)

#undef LOAD_MSG_0_2
#define LOAD_MSG_0_2(b0, b1) \
  do { b0 = vcombine_u64(vget_high_u64(m0), vget_high_u64(m1)); b1 = vcombine_u64(vget_high_u64(m2), vget_high_u64(m3)); } while(0)

#undef LOAD_MSG_0_3
#define LOAD_MSG_0_3(b0, b1) \
  do { b0 = vcombine_u64(vget_low_u64(m4), vget_low_u64(m5)); b1 = vcombine_u64(vget_low_u64(m6), vget_low_u64(m7)); } while(0)

#undef LOAD_MSG_0_4
#define LOAD_MSG_0_4(b0, b1) \
  do { b0 = vcombine_u64(vget_high_u64(m4), vget_high_u64(m5)); b1 = vcombine_u64(vget_high_u64(m6), vget_high_u64(m7)); } while(0)

#undef LOAD_MSG_1_1
#define LOAD_MSG_1_1(b0, b1) \
  do { b0 = vcombine_u64(vget_low_u64(m7), vget_low_u64(m2)); b1 = vcombine_u64(vget_high_u64(m4), vget_high_u64(m6)); } while(0)

#undef LOAD_MSG_1_2
#define LOAD_MSG_1_2(b0, b1) \
  do { b0 = vcombine_u64(vget_low_u64(m5), vget_low_u64(m4)); b1 = vextq_u64(m7, m3, 1); } while(0)

#undef LOAD_MSG_1_3
#define LOAD_MSG_1_3(b0, b1) \
  do { b0 = vextq_u64(m0, m0, 1); b1 = vcombine_u64(vget_high_u64(m5), vget_high_u64(m2)); } while(0)

#undef LOAD_MSG_1_4
#define LOAD_MSG_1_4(b0, b1) \
  do { b0 = vcombine_u64(vget_low_u64(m6), vget_low_u64(m1)); b1 = vcombine_u64(vget_high_u64(m3), vget_high_u64(m1)); } while(0)

#undef LOAD_MSG_2_1
#define LOAD_MSG_2_1(b0, b1) \
  do { b0 = vextq_u64(m5, m6, 1); b1 = vcombine_u64(vget_high_u64(m2), vget_high_u64(m7)); } while(0)

#undef LOAD_MSG_2_2
#define LOAD_MSG_2_2(b0, b1) \
  do { b0 = vcombine_u64(vget_low_u64(m4), vget_low_u64(m0)); b1 = vcombine_u64(vget_low_u64(m1), vget_high_u64(m6)); } while(0)

#undef LOAD_MSG_2_3
#define LOAD_MSG_2_3(b0, b1) \
  do { b0 = vcombine_u64(vget_low_u64(m5), vget_high_u64(m1)); b1 = vcombine_u64(vget_high_u64(m3), vget_high_u64(m4)); } while(0)

#undef LOAD_MSG_2_4
#define LOAD_MSG_2_4(b0, b1) \
  do { b0 = vcombine_u64(vget_low_u64(m7), vget_low_u64(m3)); b1 = vextq_u64(m0, m2, 1); } while(0)

#undef LOAD_MSG_3_1
#define LOAD_MSG_3_1(b0, b1) \
  do { b0 = vcombine_u64(vget_high_u64(m3), vget_high_u64(m1)); b1 = vcombine_u64(vget_high_u64(m6), vget_high_u64(m5)); } while(0)

#undef LOAD_MSG_3_2
#define LOAD_MSG_3_2(b0, b1) \
  do { b0 = vcombine_u64(vget_high_u64(m4), vget_high_u64(m0)); b1 = vcombine_u64(vget_low_u64(m6), vget_low_u64(m7)); } while(0)

#undef LOAD_MSG_3_3
#define LOAD_MSG_3_3(b0, b1) \
  do { b0 = vcombine_u64(vget_low_u64(m1), vget_high_u64(m2)); b1 = vcombine_u64(vget_low_u64(m2), vget_high_u64(m7)); } while(0)

#undef LOAD_MSG_3_4
#define LOAD_MSG_3_4(b0, b1) \
  do { b0 = vcombine_u64(vget_low_u64(m3), vget_low_u64(m5)); b1 = vcombine_u64(vget_low_u64(m0), vget_low_u64(m4)); } while(0)

#undef LOAD_MSG_4_1
#define LOAD_MSG_4_1(b0, b1) \
  do { b0 = vcombine_u64(vget_high_u64(m4), vget_high_u64(m2)); b1 = vcombine_u64(vget_low_u64(m1), vget_low_u64(m5)); } while(0)

#undef LOAD_MSG_4_2
#define LOAD_MSG_4_2(b0, b1) \
  do { b0 = vcombine_u64(vget_low_u64(m0), vget_high_u64(m3)); b1 = vcombine_u64(vget_low_u64(m2), vget_high_u64(m7)); } while(0)

#undef LOAD_MSG_4_3
#define LOAD_MSG_4_3(b0, b1) \
  do { b0 = vcombine_u64(vget_low_u64(m7), vget_high_u64(m5)); b1 = vcombine_u64(vget_low_u64(m3), vget_high_u64(m1)); } while(0)

#undef LOAD_MSG_4_4
#define LOAD_MSG_4_4(b0, b1) \
  do { b0 = vextq_u64(m0, m6, 1); b1 = vcombine_u64(vget_low_u64(m4), vget_high_u64(m6)); } while(0)

#undef LOAD_MSG_5_1
#define LOAD_MSG_5_1(b0, b1) \
  do { b0 = vcombine_u64(vget_low_u64(m1), vget_low_u64(m3)); b1 = vcombine_u64(vget_low_u64(m0), vget_low_u64(m4)); } while(0)

#undef LOAD_MSG_5_2
#define LOAD_MSG_5_2(b0, b1) \
  do { b0 = vcombine_u64(vget_low_u64(m6), vget_low_u64(m5)); b1 = vcombine_u64(vget_high_u64(m5), vget_high_u64(m1)); } while(0)

#undef LOAD_MSG_5_3
#define LOAD_MSG_5_3(b0, b1) \
  do { b0 = vcombine_u64(vget_low_u64(m2), vget_high_u64(m3)); b1 = vcombine_u64(vget_high_u64(m7), vget_high_u64(m0)); } while(0)

#undef LOAD_MSG_5_4
#define LOAD_MSG_5_4(b0, b1) \
  do { b0 = vcombine_u64(vget_high_u64(m6), vget_high_u64(m2)); b1 = vcombine_u64(vget_low_u64(m7), vget_high_u64(m4)); } while(0)

#undef LOAD_MSG_6_1
#define LOAD_MSG_6_1(b0, b1) \
  do { b0 = vcombine_u64(vget_low_u64(m6), vget_high_u64(m0)); b1 = vcombine_u64(vget_low_u64(m7), vget_low_u64(m2)); } while(0)

#undef LOAD_MSG_6_2
#define LOAD_MSG_6_2(b0, b1) \
  do { b0 = vcombine_u64(vget_high_u64(m2), vget_high_u64(m7)); b1 = vextq_u64(m6, m5, 1); } while(0)

#undef LOAD_MSG_6_3
#define LOAD_MSG_6_3(b0, b1) \
  do { b0 = vcombine_u64(vget_low_u64(m0), vget_low_u64(m3)); b1 = vextq_u64(m4, m4, 1); } while(0)

#undef LOAD_MSG_6_4
#define LOAD_MSG_6_4(b0, b1) \
  do { b0 = vcombine_u64(vget_high_u64(m3), vget_high_u64(m1)); b1 = vcombine_u64(vget_low_u64(m1), vget_high_u64(m5)); } while(0)

#undef LOAD_MSG_7_1
#define LOAD_MSG_7_1(b0, b1) \
  do { b0 = vcombine_u64(vget_high_u64(m6), vget_high_u64(m3)); b1 = vcombine_u64(vget_low_u64(m6), vget_high_u64(m1)); } while(0)

#undef LOAD_MSG_7_2
#define LOAD_MSG_7_2(b0, b1) \
  do { b0 = vextq_u64(m5, m7, 1); b1 = vcombine_u64(vget_high_u64(m0), vget_high_u64(m4)); } while(0)

#undef LOAD_MSG_7_3
#define LOAD_MSG_7_3(b0, b1) \
  do { b0 = vcombine_u64(vget_high_u64(m2), vget_high_u64(m7)); b1 = vcombine_u64(vget_low_u64(m4), vget_low_u64(m1)); } while(0)

#undef LOAD_MSG_7_4
#define LOAD_MSG_7_4(b0, b1) \
  do { b0 = vcombine_u64(vget_low_u64(m0), vget_low_u64(m2)); b1 = vcombine_u64(vget_low_u64(m3), vget_low_u64(m5)); } while(0)

#undef LOAD_MSG_8_1
#define LOAD_MSG_8_1(b0, b1) \
  do { b0 = vcombine_u64(vget_low_u64(m3), vget_low_u64(m7)); b1 = vextq_u64(m5, m0, 1); } while(0)

#undef LOAD_MSG_8_2
#define LOAD_MSG_8_2(b0, b1) \
  do { b0 = vcombine_u64(vget_high_u64(m7), vget_high_u64(m4)); b1 = vextq_u64(m1, m4, 1); } while(0)

#undef LOAD_MSG_8_3
#define LOAD_MSG_8_3(b0, b1) \
  do { b0 = m6; b1 = vextq_u64(m0, m5, 1); } while(0)

#undef LOAD_MSG_8_4
#define LOAD_MSG_8_4(b0, b1) \
  do { b0 = vcombine_u64(vget_low_u64(m1), vget_high_u64(m3)); b1 = m2; } while(0)

#undef LOAD_MSG_9_1
#define LOAD_MSG_9_1(b0, b1) \
  do { b0 = vcombine_u64(vget_low_u64(m5), vget_low_u64(m4)); b1 = vcombine_u64(vget_high_u64(m3), vget_high_u64(m0)); } while(0)

#undef LOAD_MSG_9_2
#define LOAD_MSG_9_2(b0, b1) \
  do { b0 = vcombine_u64(vget_low_u64(m1), vget_low_u64(m2)); b1 = vcombine_u64(vget_low_u64(m3), vget_high_u64(m2)); } while(0)

#undef LOAD_MSG_9_3
#define LOAD_MSG_9_3(b0, b1) \
  do { b0 = vcombine_u64(vget_high_u64(m7), vget_high_u64(m4)); b1 = vcombine_u64(vget_high_u64(m1), vget_high_u64(m6)); } while(0)

#undef LOAD_MSG_9_4
#define LOAD_MSG_9_4(b0, b1) \
  do { b0 = vextq_u64(m5, m7, 1); b1 = vcombine_u64(vget_low_u64(m6), vget_low_u64(m0)); } while(0)

#undef LOAD_MSG_10_1
#define LOAD_MSG_10_1(b0, b1) \
  do { b0 = vcombine_u64(vget_low_u64(m0), vget_low_u64(m1)); b1 = vcombine_u64(vget_low_u64(m2), vget_low_u64(m3)); } while(0)

#undef LOAD_MSG_10_2
#define LOAD_MSG_10_2(b0, b1) \
  do { b0 = vcombine_u64(vget_high_u64(m0), vget_high_u64(m1)); b1 = vcombine_u64(vget_high_u64(m2), vget_high_u64(m3)); } while(0)

#undef LOAD_MSG_10_3
#define LOAD_MSG_10_3(b0, b1) \
  do { b0 = vcombine_u64(vget_low_u64(m4), vget_low_u64(m5)); b1 = vcombine_u64(vget_low_u64(m6), vget_low_u64(m7)); } while(0)

#undef LOAD_MSG_10_4
#define LOAD_MSG_10_4(b0, b1) \
  do { b0 = vcombine_u64(vget_high_u64(m4), vget_high_u64(m5)); b1 = vcombine_u64(vget_high_u64(m6), vget_high_u64(m7)); } while(0)

#undef LOAD_MSG_11_1
#define LOAD_MSG_11_1(b0, b1) \
  do { b0 = vcombine_u64(vget_low_u64(m7), vget_low_u64(m2)); b1 = vcombine_u64(vget_high_u64(m4), vget_high_u64(m6)); } while(0)

#undef LOAD_MSG_11_2
#define LOAD_MSG_11_2(b0, b1) \
  do { b0 = vcombine_u64(vget_low_u64(m5), vget_low_u64(m4)); b1 = vextq_u64(m7, m3, 1); } while(0)

#undef LOAD_MSG_11_3
#define LOAD_MSG_11_3(b0, b1) \
  do { b0 = vextq_u64(m0, m0, 1); b1 = vcombine_u64(vget_high_u64(m5), vget_high_u64(m2)); } while(0)

#undef LOAD_MSG_11_4
#define LOAD_MSG_11_4(b0, b1) \
  do { b0 = vcombine_u64(vget_low_u64(m6), vget_low_u64(m1)); b1 = vcombine_u64(vget_high_u64(m3), vget_high_u64(m1)); } while(0)

#define vrorq_n_u64_32(x) vreinterpretq_u64_u32(vrev64q_u32(vreinterpretq_u32_u64((x))))

#define vrorq_n_u64_24(x) vcombine_u64( \
      vreinterpret_u64_u8(vext_u8(vreinterpret_u8_u64(vget_low_u64(x)), vreinterpret_u8_u64(vget_low_u64(x)), 3)), \
      vreinterpret_u64_u8(vext_u8(vreinterpret_u8_u64(vget_high_u64(x)), vreinterpret_u8_u64(vget_high_u64(x)), 3)))

#define vrorq_n_u64_16(x) vcombine_u64( \
      vreinterpret_u64_u8(vext_u8(vreinterpret_u8_u64(vget_low_u64(x)), vreinterpret_u8_u64(vget_low_u64(x)), 2)), \
      vreinterpret_u64_u8(vext_u8(vreinterpret_u8_u64(vget_high_u64(x)), vreinterpret_u8_u64(vget_high_u64(x)), 2)))

#define vrorq_n_u64_63(x) veorq_u64(vaddq_u64(x, x), vshrq_n_u64(x, 63))

#undef G1
#define G1(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h,b0,b1) \
  do { \
    row1l = vaddq_u64(vaddq_u64(row1l, b0), row2l); \
    row1h = vaddq_u64(vaddq_u64(row1h, b1), row2h); \
    row4l = veorq_u64(row4l, row1l); row4h = veorq_u64(row4h, row1h); \
    row4l = vrorq_n_u64_32(row4l); row4h = vrorq_n_u64_32(row4h); \
    row3l = vaddq_u64(row3l, row4l); row3h = vaddq_u64(row3h, row4h); \
    row2l = veorq_u64(row2l, row3l); row2h = veorq_u64(row2h, row3h); \
    row2l = vrorq_n_u64_24(row2l); row2h = vrorq_n_u64_24(row2h); \
  } while(0)

#undef G2
#define G2(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h,b0,b1) \
  do { \
    row1l = vaddq_u64(vaddq_u64(row1l, b0), row2l); \
    row1h = vaddq_u64(vaddq_u64(row1h, b1), row2h); \
    row4l = veorq_u64(row4l, row1l); row4h = veorq_u64(row4h, row1h); \
    row4l = vrorq_n_u64_16(row4l); row4h = vrorq_n_u64_16(row4h); \
    row3l = vaddq_u64(row3l, row4l); row3h = vaddq_u64(row3h, row4h); \
    row2l = veorq_u64(row2l, row3l); row2h = veorq_u64(row2h, row3h); \
    row2l = vrorq_n_u64_63(row2l); row2h = vrorq_n_u64_63(row2h); \
  } while(0)

#define DIAGONALIZE(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h) \
  do { \
    uint64x2_t t0 = vextq_u64(row2l, row2h, 1); \
    uint64x2_t t1 = vextq_u64(row2h, row2l, 1); \
    row2l = t0; row2h = t1; t0 = row3l;  row3l = row3h; row3h = t0; \
    t0 = vextq_u64(row4h, row4l, 1); t1 = vextq_u64(row4l, row4h, 1); \
    row4l = t0; row4h = t1; \
  } while(0)

#define UNDIAGONALIZE(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h) \
  do { \
    uint64x2_t t0 = vextq_u64(row2h, row2l, 1); \
    uint64x2_t t1 = vextq_u64(row2l, row2h, 1); \
    row2l = t0; row2h = t1; t0 = row3l; row3l = row3h; row3h = t0; \
    t0 = vextq_u64(row4l, row4h, 1); t1 = vextq_u64(row4h, row4l, 1); \
    row4l = t0; row4h = t1; \
  } while(0)

#undef ROUND
#define ROUND(r) \
  do { \
    uint64x2_t b0, b1; \
    LOAD_MSG_ ##r ##_1(b0, b1); \
    G1(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h,b0,b1); \
    LOAD_MSG_ ##r ##_2(b0, b1); \
    G2(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h,b0,b1); \
    DIAGONALIZE(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h); \
    LOAD_MSG_ ##r ##_3(b0, b1); \
    G1(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h,b0,b1); \
    LOAD_MSG_ ##r ##_4(b0, b1); \
    G2(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h,b0,b1); \
    UNDIAGONALIZE(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h); \
  } while(0)

static void blake2b_compress( blake2b_state *S, const uint8_t block[BLAKE2B_BLOCKBYTES] )
{
  const uint64x2_t m0 = vreinterpretq_u64_u8(vld1q_u8(&block[  0]));
  const uint64x2_t m1 = vreinterpretq_u64_u8(vld1q_u8(&block[ 16]));
  const uint64x2_t m2 = vreinterpretq_u64_u8(vld1q_u8(&block[ 32]));
  const uint64x2_t m3 = vreinterpretq_u64_u8(vld1q_u8(&block[ 48]));
  const uint64x2_t m4 = vreinterpretq_u64_u8(vld1q_u8(&block[ 64]));
  const uint64x2_t m5 = vreinterpretq_u64_u8(vld1q_u8(&block[ 80]));
  const uint64x2_t m6 = vreinterpretq_u64_u8(vld1q_u8(&block[ 96]));
  const uint64x2_t m7 = vreinterpretq_u64_u8(vld1q_u8(&block[112]));

  uint64x2_t row1l, row1h, row2l, row2h;
  uint64x2_t row3l, row3h, row4l, row4h;

  const uint64x2_t h0 = row1l = vld1q_u64(&S->h[0]);
  const uint64x2_t h1 = row1h = vld1q_u64(&S->h[2]);
  const uint64x2_t h2 = row2l = vld1q_u64(&S->h[4]);
  const uint64x2_t h3 = row2h = vld1q_u64(&S->h[6]);

  row3l = vld1q_u64(&blake2b_IV[0]);
  row3h = vld1q_u64(&blake2b_IV[2]);
  row4l = veorq_u64(vld1q_u64(&blake2b_IV[4]), vld1q_u64(&S->t[0]));
  row4h = veorq_u64(vld1q_u64(&blake2b_IV[6]), vld1q_u64(&S->f[0]));

  ROUND( 0 );
  ROUND( 1 );
  ROUND( 2 );
  ROUND( 3 );
  ROUND( 4 );
  ROUND( 5 );
  ROUND( 6 );
  ROUND( 7 );
  ROUND( 8 );
  ROUND( 9 );
  ROUND( 10 );
  ROUND( 11 );

  vst1q_u64(&S->h[0], veorq_u64(h0, veorq_u64(row1l, row3l)));
  vst1q_u64(&S->h[2], veorq_u64(h1, veorq_u64(row1h, row3h)));
  vst1q_u64(&S->h[4], veorq_u64(h2, veorq_u64(row2l, row4l)));
  vst1q_u64(&S->h[6], veorq_u64(h3, veorq_u64(row2h, row4h)));
}

#undef G
#undef ROUND

int blake2b_update( blake2b_state *S, const void *pin, size_t inlen )
{
  const unsigned char * in = (const unsigned char *)pin;
  if( inlen > 0 )
  {
    size_t left = S->buflen;
    size_t fill = BLAKE2B_BLOCKBYTES - left;
    if( inlen > fill )
    {
      S->buflen = 0;
      memcpy( S->buf + left, in, fill ); /* Fill buffer */
      blake2b_increment_counter( S, BLAKE2B_BLOCKBYTES );
      blake2b_compress( S, S->buf ); /* Compress */
      in += fill; inlen -= fill;
      while(inlen > BLAKE2B_BLOCKBYTES) {
        blake2b_increment_counter(S, BLAKE2B_BLOCKBYTES);
        blake2b_compress( S, in );
        in += BLAKE2B_BLOCKBYTES;
        inlen -= BLAKE2B_BLOCKBYTES;
      }
    }
    memcpy( S->buf + S->buflen, in, inlen );
    S->buflen += inlen;
  }
  return 0;
}

int blake2b_final( blake2b_state *S, void *out, size_t outlen )
{
  uint8_t buffer[BLAKE2B_OUTBYTES] = {0};
  size_t i;

  if( out == NULL || outlen < S->outlen )
    return -1;

  if( blake2b_is_lastblock( S ) )
    return -1;

  blake2b_increment_counter( S, S->buflen );
  blake2b_set_lastblock( S );
  memset( S->buf + S->buflen, 0, BLAKE2B_BLOCKBYTES - S->buflen ); /* Padding */
  blake2b_compress( S, S->buf );

  for( i = 0; i < 8; ++i ) /* Output full hash to temp buffer */
    store64( buffer + sizeof( S->h[i] ) * i, S->h[i] );

  memcpy( out, buffer, S->outlen );
  secure_zero_memory(buffer, sizeof(buffer));
  return 0;
}

/* inlen, at least, should be uint64_t. Others can be size_t. */
int blake2b( void *out, size_t outlen, const void *in, size_t inlen, const void *key, size_t keylen )
{
  blake2b_state S[1];

  /* Verify parameters */
  if ( NULL == in && inlen > 0 ) return -1;

  if ( NULL == out ) return -1;

  if( NULL == key && keylen > 0 ) return -1;

  if( !outlen || outlen > BLAKE2B_OUTBYTES ) return -1;

  if( keylen > BLAKE2B_KEYBYTES ) return -1;

  if( keylen > 0 )
  {
    if( blake2b_init_key( S, outlen, key, keylen ) < 0 ) return -1;
  }
  else
  {
    if( blake2b_init( S, outlen ) < 0 ) return -1;
  }

  blake2b_update( S, ( const uint8_t * )in, inlen );
  blake2b_final( S, out, outlen );
  return 0;
}

int blake2( void *out, size_t outlen, const void *in, size_t inlen, const void *key, size_t keylen ) {
  return blake2b(out, outlen, in, inlen, key, keylen);
}

#if defined(SUPERCOP)
int crypto_hash( unsigned char *out, unsigned char *in, unsigned long long inlen )
{
  return blake2b( out, BLAKE2B_OUTBYTES, in, inlen, NULL, 0 );
}
#endif

#if defined(BLAKE2B_SELFTEST)
#include <string.h>
#include "blake2-kat.h"
int main( void )
{
  uint8_t key[BLAKE2B_KEYBYTES];
  uint8_t buf[BLAKE2_KAT_LENGTH];
  size_t i, step;

  for( i = 0; i < BLAKE2B_KEYBYTES; ++i )
    key[i] = ( uint8_t )i;

  for( i = 0; i < BLAKE2_KAT_LENGTH; ++i )
    buf[i] = ( uint8_t )i;

  /* Test simple API */
  for( i = 0; i < BLAKE2_KAT_LENGTH; ++i )
  {
    uint8_t hash[BLAKE2B_OUTBYTES];
    blake2b( hash, BLAKE2B_OUTBYTES, buf, i, key, BLAKE2B_KEYBYTES );

    if( 0 != memcmp( hash, blake2b_keyed_kat[i], BLAKE2B_OUTBYTES ) )
    {
      goto fail;
    }
  }

  /* Test streaming API */
  for(step = 1; step < BLAKE2B_BLOCKBYTES; ++step) {
    for (i = 0; i < BLAKE2_KAT_LENGTH; ++i) {
      uint8_t hash[BLAKE2B_OUTBYTES];
      blake2b_state S;
      uint8_t * p = buf;
      size_t mlen = i;
      int err = 0;

      if( (err = blake2b_init_key(&S, BLAKE2B_OUTBYTES, key, BLAKE2B_KEYBYTES)) < 0 ) {
        goto fail;
      }

      while (mlen >= step) {
        if ( (err = blake2b_update(&S, p, step)) < 0 ) {
          goto fail;
        }
        mlen -= step;
        p += step;
      }
      if ( (err = blake2b_update(&S, p, mlen)) < 0) {
        goto fail;
      }
      if ( (err = blake2b_final(&S, hash, BLAKE2B_OUTBYTES)) < 0) {
        goto fail;
      }

      if (0 != memcmp(hash, blake2b_keyed_kat[i], BLAKE2B_OUTBYTES)) {
        goto fail;
      }
    }
  }

  puts( "ok" );
  return 0;
fail:
  puts("error");
  return -1;
}
#endif
