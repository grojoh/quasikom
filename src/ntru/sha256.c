///////////////////////////////////////////////////////////////////////////////
// sha256.c: A simple, portable implementation of the SHA256 hash function.  //
// This file is part of project QUASIKOM ("Post-Quantum Secure Communication //
// for the Internet of Things"), supported by Netidee <http://netidee.at/>.  //
// Project repository on GitHub: <http://www.github.com/grojoh/quasikom/>.   //
// Version 1.0.0 (2018-01-29), see project repository for latest version.    //
// Author: Johann Groszschaedl <http://sites.google.com/site/groszschaedl/>. //
// License: GPLv3 (see LICENSE file), other licenses available on request.   //
// Copyright (C) 2016 Southern Storm Software, Pty Ltd.                      //
// Copyright (C) 2018 Johann Groszschaedl.                                   //
// ------------------------------------------------------------------------- //
// This program is free software: you can redistribute it and/or modify it   //
// under the terms of the GNU General Public License as published by the     //
// Free Software Foundation, either version 3 of the License, or (at your    //
// option) any later version. This program is distributed in the hope that   //
// it will be useful, but WITHOUT ANY WARRANTY; without even the implied     //
// warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the  //
// GNU General Public License for more details. You should have received a   //
// copy of the GNU General Public License along with this program. If not,   //
// see <http://www.gnu.org/licenses/>.                                       //
///////////////////////////////////////////////////////////////////////////////


///////////////////////////////////////////////////////////////////////////////
// The source code in this file is a modification of an MIT-licensed SHA256  //
// implementation written by Rhys Weatherley, which is available on GitHub   //
// at <http://github.com/rweather/noise-c/tree/master/src/crypto/sha2/>. The //
// original work contains the following copyright and permission notices:    //
// Copyright (C) 2016 Southern Storm Software, Pty Ltd.                      //
// Permission is hereby granted, free of charge, to any person obtaining a   //
// copy of this software and associated documentation files (the "Software") //
// to deal in the Software without restriction, including without limitation //
// the rights to use, copy, modify, merge, publish, distribute, sublicense,  //
// and/or sell copies of the Software, and to permit persons to whom the     //
// Software is furnished to do so, subject to the following conditions:      //
// The above copyright notice and this permission notice shall be included   //
// in all copies or substantial portions of the Software.                    //
///////////////////////////////////////////////////////////////////////////////


// SHA256 is a cryptographic hash function standardized by the U.S. National
// Institute of Standards and Technology (NIST) and specified in FIPS 180-4
// (see <http://doi.org/10.6028/NIST.FIPS.180-4>). The present implementation
// provides both a high-level and a low-level API, whereby the former consists
// of just a single function, namely sha256_hash(). On the other hand, the
// low-level API comes with the standard IUF (init, update, final) functions
// and is generally preferred for hashing very large or fragmented data. The
// high-level sha256_hash() function requires the entire data to be hashed in
// RAM, which can be problematic in some settings. For example, the high-level
// function does not allow one to hash a large file stored on the hard disk if
// its size exceeds the available RAM capacity. But when using the low-level
// API, a large file can be processed in (small) parts by simply loading the
// parts into RAM and calling sha256_update() until the entire file is hashed.
// In this way, it is possible to hash data of arbitrary size with constant
// memory usage. Another example showing the benefits of the low-level API is
// online processing (see <http://en.wikipedia.org/wiki/Online_algorithm>), in
// particular streaming applications, where the data to be hashed comes in
// streams and is highly fragmented. The sha256_hash() function requires the
// receiver to buffer the entire data, which can easily exceed the available
// RAM capacity. However, when using the low-level API, the chunks of data can
// be processed as they are received by calling the sha256_update() function,
// thereby avoiding the need to buffer large amounts of data.


#include <string.h>
#include "sha256.h"
#include "config.h"

// AVRSHA_USE_ASM is defined (or not defined) in config.h
#ifdef AVRSHA_USE_ASM
extern void sha256_compress_avr(uint32_t *hval, const uint8_t *m);
#endif

// Data type to efficiently access the bytes of 32-bit word
typedef union
{ 
  uint32_t w; 
  uint8_t b[4];
} word32_t;

// Macro to get the minimum of two numbers
#define MIN(x, y) (((x) < (y)) ? (x) : (y))
// Macro to get the maximum of two numbers
#define MAX(x, y) (((x) > (y)) ? (x) : (y))

// Macro to right-shift a 32-bit word by n bits
#define SHR32(x, n) ((x) >> (n))
// Macro to right-rotate a 32-bit word by n bits
#define ROR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

// Macro to left-shift a 32-bit word by n bits
#define SHL32(x, n) ((x)) << (n))
// Macro to left-rotate a 32-bit word by n bits
#define ROL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

// Macro for the Choice function
#define CHO32(x, y, z) (((x) & ((y) ^ (z))) ^ (z))
// Macro for the Majority function
#define MAJ32(x, y, z) ((((x) | (y)) & (z)) | ((x) & (y)))

// Macro for the Sigma0 ("Big Sigma Zero") function
#define BSZ32(x) (ROR32((x), 2) ^ ROR32((x), 13) ^ ROR32((x), 22))
// Macro for the Sigma1 ("Big Sigma One") function
#define BSO32(x) (ROR32((x), 6) ^ ROR32((x), 11) ^ ROR32((x), 25))

// Macro for the sigma0 ("Small Sigma Zero") function
#define SSZ32(x) (ROR32((x), 7) ^ ROR32((x), 18) ^ SHR32((x), 3))
// Macro for the simga1 ("Small Sigma One") function
#define SSO32(x) (ROR32((x), 17) ^ ROR32((x), 19) ^ SHR32((x), 10))

// Macro for the full SHA256 round function
#define SHA256_ROUND(a, b, c, d, e, f, g, h, s)   \
  (h) += ((s) + BSO32(e) + CHO32((e), (f), (g))), \
  (d) += (h),                                     \
  (h) += (BSZ32(a) + MAJ32((a), (b), (c)))

// Constant to determine the host byte-order
static const word32_t is_little_endian = { 1 };

// Round constants as specified in FIPS180-4 Sect 4.4.2
static const uint32_t k[64] = {
  0x428A2F98UL, 0x71374491UL, 0xB5C0FBCFUL, 0xE9B5DBA5UL,
  0x3956C25BUL, 0x59F111F1UL, 0x923F82A4UL, 0xAB1C5ED5UL,
  0xD807AA98UL, 0x12835B01UL, 0x243185BEUL, 0x550C7DC3UL,
  0x72BE5D74UL, 0x80DEB1FEUL, 0x9BDC06A7UL, 0xC19BF174UL,
  0xE49B69C1UL, 0xEFBE4786UL, 0x0FC19DC6UL, 0x240CA1CCUL,
  0x2DE92C6FUL, 0x4A7484AAUL, 0x5CB0A9DCUL, 0x76F988DAUL,
  0x983E5152UL, 0xA831C66DUL, 0xB00327C8UL, 0xBF597FC7UL,
  0xC6E00BF3UL, 0xD5A79147UL, 0x06CA6351UL, 0x14292967UL,
  0x27B70A85UL, 0x2E1B2138UL, 0x4D2C6DFCUL, 0x53380D13UL,
  0x650A7354UL, 0x766A0ABBUL, 0x81C2C92EUL, 0x92722C85UL,
  0xA2BFE8A1UL, 0xA81A664BUL, 0xC24B8B70UL, 0xC76C51A3UL,
  0xD192E819UL, 0xD6990624UL, 0xF40E3585UL, 0x106AA070UL,
  0x19A4C116UL, 0x1E376C08UL, 0x2748774CUL, 0x34B0BCB5UL,
  0x391C0CB3UL, 0x4ED8AA4AUL, 0x5B9CCA4FUL, 0x682E6FF3UL,
  0x748F82EEUL, 0x78A5636FUL, 0x84C87814UL, 0x8CC70208UL,
  0x90BEFFFAUL, 0xA4506CEBUL, 0xBEF9A3F7UL, 0xC67178F2UL
};


/*
 * Conversion of a byte-array consisting of four bytes given in big endian
 * representation to a 32-bit unsigned integer in host byte-order (which is
 * little endian for many embedded platforms, e.g. Atmel AVR or TI MSP430).
 */

static uint32_t bytes_to_word(const uint8_t *byte_array)
{
  word32_t temp;
  
  if (is_little_endian.b[0] == 1)
  { // host byte-order is little endian
    temp.b[0] = byte_array[3];
    temp.b[1] = byte_array[2];
    temp.b[2] = byte_array[1];
    temp.b[3] = byte_array[0];
  }
  else
  { // host byte-order is big endian
    temp.w = *((uint32_t *) byte_array);
  }
  
  return temp.w;
}


static void word_to_bytes(uint8_t *byte_array, uint32_t word)
{
  word32_t temp = { word };
  
  if (is_little_endian.b[0] == 1)
  { // host byte-order is little endian
    byte_array[0] = temp.b[3];
    byte_array[1] = temp.b[2];
    byte_array[2] = temp.b[1];
    byte_array[3] = temp.b[0];
  }
  else
  { // host byte-order is big endian
    *((uint32_t *) byte_array) = temp.w;
  }
}


void sha256_init(sha256_context_t *ctx)
{
  // Set initial hash value (see FIPS180-4 Sect 5.3.3)
  ctx->hval[0] = 0x6A09E667UL;
  ctx->hval[1] = 0xBB67AE85UL;
  ctx->hval[2] = 0x3C6EF372UL;
  ctx->hval[3] = 0xA54FF53AUL;
  ctx->hval[4] = 0x510E527FUL;
  ctx->hval[5] = 0x9B05688CUL;
  ctx->hval[6] = 0x1F83D9ABUL;
  ctx->hval[7] = 0x5BE0CD19UL;
  // No data was processed so far
  ctx->length = 0;
  // The 64-byte buffer is emptry
  ctx->mbytes = 0;
}


static void sha256_compress_c99(uint32_t *hval, const uint8_t *m)
{
  int i, j = 8;
  uint32_t t1, t2, s[16], w[64];
  
  // 1st loop: Initialize the 8 state-words (8 working variables) with current
  // hash value (we duplicate the state to simplify the addressing of words in
  // the 4th loop, i.e. we have 16 words in array s where s[0..7] = s[8..15])
  for (i = 0; i < 8; i ++) s[i] = s[i+8] = hval[i];
  
  // 2nd loop: Convert 16-word message block from big endian to host byte-order
  for (i = 0; i < 16; i ++) w[i] = bytes_to_word(&(m[4*i]));
  
  // 3rd loop: Extend the first 16 words to 64 words (see FIPS180-4 Sect 6.2.2)
  for (i = 16; i < 64; i ++)
    w[i] = w[i-16] + w[i-7] + (SSZ32(w[i-15])) + (SSO32(w[i-2]));
  
  // 4th loop: Main loop of the compression function (see FIPS180-4 Sect 6.2.2)
  // Note that j has been initialized with 8
  for (i = 0; i < 64; i ++)
  {
    t1 = s[j+7] + BSO32(s[j+4]) + CHO32(s[j+4], s[j+5], s[j+6]) + k[i] + w[i];
    t2 = BSZ32(s[j]) + MAJ32(s[j], s[j+1], s[j+2]);
    s[j+3] = s[j+3] + t1;
    s[--j] = t1 + t2;
    if (j == 0) { j = 8; memcpy(&(s[8]), s, 32); }
    // printf("i = %02d: %08x%08x%08x%08x%08x%08x%08x%08x\n", i, \
    //   s[j], s[j+1], s[j+2], s[j+3], s[j+4], s[j+5], s[j+6], s[j+7]);
  }
  
  // 5th loop: Add the 8 state-words to the current (intermediate) hash value
  for (i = 0; i < 8; i ++) hval[i] += s[i];
}


static void sha256_compress_unrolled(uint32_t *hval, const uint8_t *m)
{
  int i;
  uint32_t w[64];
  // 8 working variables (initialized with the current hash value)
  uint32_t a = hval[0], b = hval[1], c = hval[2], d = hval[3];
  uint32_t e = hval[4], f = hval[5], g = hval[6], h = hval[7];
  
  // Convert 16-word message block from big endian to host byte-order
  for (i = 0; i < 16; i ++) w[i] = bytes_to_word(&(m[4*i]));
  
  // Extend the first 16 words to 64 words (see FIPS180-4 Sect 6.2.2)
  for (i = 16; i < 64; i ++)
    w[i] = w[i-16] + w[i-7] + (SSZ32(w[i-15])) + (SSO32(w[i-2]));
  
  // Main loop of the compression function (see FIPS180-4 Sect 6.2.2)
  for (i = 0; i < 64; i += 8)
  {
    SHA256_ROUND(a, b, c, d, e, f, g, h, k[i]+w[i]);
    SHA256_ROUND(h, a, b, c, d, e, f, g, k[i+1]+w[i+1]);
    SHA256_ROUND(g, h, a, b, c, d, e, f, k[i+2]+w[i+2]);
    SHA256_ROUND(f, g, h, a, b, c, d, e, k[i+3]+w[i+3]);
    SHA256_ROUND(e, f, g, h, a, b, c, d, k[i+4]+w[i+4]);
    SHA256_ROUND(d, e, f, g, h, a, b, c, k[i+5]+w[i+5]);
    SHA256_ROUND(c, d, e, f, g, h, a, b, k[i+6]+w[i+6]);
    SHA256_ROUND(b, c, d, e, f, g, h, a, k[i+7]+w[i+7]);
  }
  
  // Add the 8 working variables to the current hash value
  hval[0] += a; hval[1] += b; hval[2] += c; hval[3] += d;
  hval[4] += e; hval[5] += f; hval[6] += g; hval[7] += h;
}


// To switch between ASM and C version of sha256_compress
// AVRSHA_USE_ASM is defined (or not defined) in config.h
#ifdef AVRSHA_USE_ASM  // use ASM version of sha256_compress
#define sha256_compress sha256_compress_avr
#else  // use C version of sha256_compress
#define sha256_compress sha256_compress_c99
#endif


void sha256_update(sha256_context_t *ctx, const void *data, size_t dlen)
{
  size_t addm, bcount = 0;
  const uint8_t *d = (const uint8_t *) data;
  
  while (bcount < dlen)
  { // bcount counts the number of processed bytes
    if ((ctx->mbytes == 0) && ((dlen - bcount) >= 64))
    {
      sha256_compress(ctx->hval, &(d[bcount]));
      ctx->length += 512;
      bcount += 64;
    }
    else
    {
      // addm is number of bytes to be copied into m[]
      addm = MIN((dlen - bcount), ((size_t) (64 - ctx->mbytes)));
      memcpy(&(ctx->mbuf[ctx->mbytes]), &(d[bcount]), addm);
      ctx->mbytes += addm;
      if (ctx->mbytes >= 64)
      {
        sha256_compress(ctx->hval, ctx->mbuf);
        ctx->mbytes = 0;
      }
      ctx->length += 8*addm;
      bcount += addm;
    }
  }
}


void sha256_final(sha256_context_t *ctx, uint8_t *hashval)
{
  int i;
  uint8_t mbytes = ctx->mbytes;
  
  if (mbytes <= 55)
  {
    ctx->mbuf[mbytes] = 0x80;
    memset(&(ctx->mbuf[mbytes+1]), 0, (55 - mbytes));
  }
  else
  {
    ctx->mbuf[mbytes] = 0x80;
    memset(&(ctx->mbuf[mbytes+1]), 0, (63 - mbytes));
    sha256_compress(ctx->hval, ctx->mbuf);
    memset(ctx->mbuf, 0, 56);
  }
  
  word_to_bytes(&(ctx->mbuf[56]), (uint32_t) (ctx->length >> 32));
  word_to_bytes(&(ctx->mbuf[60]), (uint32_t) (ctx->length));
  
  sha256_compress(ctx->hval, ctx->mbuf);
  
  for (i = 0; i < 8; i ++)
    word_to_bytes(&(hashval[4*i]), ctx->hval[i]);
}


void sha256_hash(uint8_t *hashval, const void *data, size_t dlen)
{
  sha256_context_t ctx;
  
  sha256_init(&ctx);
  sha256_update(&ctx, data, dlen);
  sha256_final(&ctx, hashval);
}
