///////////////////////////////////////////////////////////////////////////////
// sha256_demo.c: A very simple demo program for the SHA256 hash function.   //
// This file is part of project QUASIKOM ("Post-Quantum Secure Communication //
// for the Internet of Things"), supported by Netidee <http://netidee.at/>.  //
// Project repository on GitHub: <http://www.github.com/grojoh/quasikom/>.   //
// Version 1.0.0 (2018-01-29), see project repository for latest version.    //
// Author: Johann Groszschaedl <http://sites.google.com/site/groszschaedl/>. //
// License: GPLv3 (see LICENSE file), other licenses available on request.   //
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


#include <stdio.h>
#include <string.h>
#include "sha256.h"
#include "utils.h"

#ifdef __AVR__
static FILE mystdout = FDEV_SETUP_STREAM(uart_putch, NULL, _FDEV_SETUP_WRITE);
#endif

/*
 * Simple test function, using test vectors provided in
 * http://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA_All.pdf
 */

int main(void)
{
  sha256_context_t ctx;
  const uint8_t string1[] = "abc";
  const uint8_t string2[] = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
  uint8_t hashval[32];
  
#ifdef __AVR__
  init_uart();
  stdout = &mystdout;
#endif
  
  // String1 requires only a single call of the compression function.
  sha256_hash(hashval, string1, 3);
  printf("message: %s\n", string1);
  xprint("hashval: ", hashval, 32);
  // BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD
  
  // String2 has a length of 56 bytes, which means that the compression
  // function is called twice, both times in the sha256_final() function.
  sha256_hash(hashval, string2, 56);
  printf("message: %s\n", string2);
  xprint("hashval: ", hashval, 32);
  // 248D6A61D20638B8E5C026930C3E6039A33CE45964FF2167F6ECEDD419DB06C1
  
  // In the following example, the 56-byte message in string2 is hashed 
  // sequentially by calling sha256_update() with two 28-byte chunks.
  sha256_init(&ctx);
  sha256_update(&ctx, string2, 28);
  sha256_update(&ctx, &(string2[28]), 28);
  sha256_final(&ctx, hashval);
  xprint("hashval: ", hashval, 32);
  // 248D6A61D20638B8E5C026930C3E6039A33CE45964FF2167F6ECEDD419DB06C1
  
  return 0;
}
