///////////////////////////////////////////////////////////////////////////////
// sha256.h: A simple, portable implementation of the SHA256 hash function.  //
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


#ifndef _SHA256_H
#define _SHA256_H

#include <stddef.h>

#ifdef _MSC_VER
typedef unsigned __int8  uint8_t;   // 8-bit unsigned integer (0~255)
typedef unsigned __int16 uint16_t;  // 16-bit unsigned integer
typedef unsigned __int32 uint32_t;  // 32-bit unsigned integer
typedef unsigned __int64 uint64_t;  // 64-bit unsigned integer
#else
#include <stdint.h>
#endif

typedef struct
{
  uint32_t hval[8];  // current (i.e. intermediate) hash value
  uint8_t mbuf[64];  // buffer for a 64-byte block of the message
  uint64_t length;   // overall length of hashed message (in bits) 
  uint8_t mbytes;    // number of bytes contained in mbuf array
} sha256_context_t;

// Low-level API
void sha256_init(sha256_context_t *ctx);
void sha256_update(sha256_context_t *ctx, const void *data, size_t dlen);
void sha256_final(sha256_context_t *ctx, uint8_t *hashval);

// High-level API
void sha256_hash(uint8_t *hashval, const void *data, size_t dlen);

#endif
