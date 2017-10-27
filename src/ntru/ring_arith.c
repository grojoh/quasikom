///////////////////////////////////////////////////////////////////////////////
// ring_arith.c: Polynomial arithmetic in NTRU ring on 8-bit AVR processors. //
// This file is part of project QUASIKOM ("Post-Quantum Secure Communication //
// for the Internet of Things"), supported by Netidee <https://netidee.at/>. //
// Project repository on github: <https://www.github.com/grojoh/quasikom/>.  //
// Version 1.0.0 (2017-02-20), see project repository for latest version.    //
// Author: Dipl.-Ing. Johann Groszschaedl (Secure Things Lab, Austria).      //
// License: GPLv3 (see LICENSE file), other licenses available on request.   //
// Copyright (C) 2017 Secure Things Lab <https://www.securethingslab.at/>.   //
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
#include "asmfncts.h" // prototypes of ASM functions
#include "ring_arith.h"
#include "testvec.h"


#define MAX(a, b) (((a) > (b)) ? (a) : (b))


void ring_mul_cfadd_c99(UINT16 *r, const UINT16 *a, UINT16 *b, int alen,
                        int blen)
{
  int N = alen-7, loop_cnt = 8*(alen>>3), i = 0, j;
  register UINT16 sum0, sum1, sum2, sum3, sum4, sum5, sum6, sum7;
  UINT16 idx;
  
  for (j = 0; j < blen; j ++) b[j] = (b[j] == 0) ? 0 : N - b[j];
  // for (j = 0; j < blen; j ++) printf("%i ", b[j]); printf("\n");
  
  while (i < loop_cnt)  // loop_cnt must be >= N and a multiple of 8
  {
    sum0 = r[i  ]; sum1 = r[i+1]; sum2 = r[i+2]; sum3 = r[i+3];
    sum4 = r[i+4]; sum5 = r[i+5]; sum6 = r[i+6]; sum7 = r[i+7];
    
    for (j = 0; j < blen; j ++)
    {
      idx = b[j];
      sum0 += a[idx++]; sum1 += a[idx++]; sum2 += a[idx++]; sum3 += a[idx++];
      sum4 += a[idx++]; sum5 += a[idx++]; sum6 += a[idx++]; sum7 += a[idx++];
      b[j] = (idx >= N) ? (idx - N) : idx;
    }
    // for (j = 0; j < blen; j ++) printf("%04x ", b[j]); printf("\n");
    
    r[i++] = sum0; r[i++] = sum1; r[i++] = sum2; r[i++] = sum3;
    r[i++] = sum4; r[i++] = sum5; r[i++] = sum6; r[i++] = sum7;
  }
}


void ring_mul_cfsub_c99(UINT16 *r, const UINT16 *a, UINT16 *b, int alen,
                        int blen)
{
  int N = alen-7, loop_cnt = 8*(alen>>3), i = 0, j;
  register UINT16 sum0, sum1, sum2, sum3, sum4, sum5, sum6, sum7;
  UINT16 idx;
  
  for (j = 0; j < blen; j ++) b[j] = (b[j] == 0) ? 0 : N - b[j];
  // for (j = 0; j < blen; j ++) printf("%i ", b[j]); printf("\n");
  
  while (i < loop_cnt)  // loop_cnt must be >= N and a multiple of 8
  {
    sum0 = r[i  ]; sum1 = r[i+1]; sum2 = r[i+2]; sum3 = r[i+3];
    sum4 = r[i+4]; sum5 = r[i+5]; sum6 = r[i+6]; sum7 = r[i+7];
    
    for (j = 0; j < blen; j ++)
    {
      idx = b[j];
      sum0 -= a[idx++]; sum1 -= a[idx++]; sum2 -= a[idx++]; sum3 -= a[idx++];
      sum4 -= a[idx++]; sum5 -= a[idx++]; sum6 -= a[idx++]; sum7 -= a[idx++];
      b[j] = (idx >= N) ? (idx - N) : idx;
    }
    // for (j = 0; j < blen; j ++) printf("%i ", b[j]); printf("\n");
    
    r[i++] = sum0; r[i++] = sum1; r[i++] = sum2; r[i++] = sum3;
    r[i++] = sum4; r[i++] = sum5; r[i++] = sum6; r[i++] = sum7;
  }
}


// Multiplication of a polynomial a(X) of degree N-1 by a sparse polynimial
// b(X) in product form, i.e. b(X) = b1(X)*b2(X) + b3(X). The multiplication
// is a "convolution" performed in the ring (Z/qZ)[X]/(X^N - 1). This function
// corresponds to the function ntru_ring_mult_product_indices() of the NTRU
// reference implementation on Github.

void ring_mul_sparse(UINT16 *r, const UINT16 *a, const SPARSE_POLY *b, \
                     int alen)
{
  int j = 0, rlen = 8*(alen>>3);  // rlen must be >= N and a multiple of 8
  int i, blen, bmax = (MAX(MAX(b->p1i_len, b->p2i_len), b->p3i_len)) >> 1;
  UINT16 rtmp[rlen], btmp[bmax];
  
  // initialize r and rtmp
  for (i = 0; i < rlen; i ++) r[i] = rtmp[i] = 0;
  
  // first multiplication: rtmp = a*b1
  blen = b->p1i_len >> 1;
  for (i = 0; i < blen; i ++) btmp[i] = b->indices[j++];
  ring_mul_cfadd(rtmp, a, btmp, alen, blen);
  for (i = 0; i < blen; i ++) btmp[i] = b->indices[j++];
  ring_mul_cfsub(rtmp, a, btmp, alen, blen);
  
  // second multiplication: r = rtmp*b2 = a*b1*b2
  blen = b->p2i_len >> 1;
  for (i = 0; i < 7; i ++) rtmp[(alen-7)+i] = rtmp[i];  
  for (i = 0; i < blen; i ++) btmp[i] = b->indices[j++];
  ring_mul_cfadd(r, rtmp, btmp, alen, blen);
  for (i = 0; i < blen; i ++) btmp[i] = b->indices[j++];
  ring_mul_cfsub(r, rtmp, btmp, alen, blen);
  
  // third multiplication: r = r + a*b3 = a*(b1*b2 + b3)
  blen = b->p3i_len >> 1;
  for (i = 0; i < blen; i ++) btmp[i] = b->indices[j++];
  ring_mul_cfadd(r, a, btmp, alen, blen);
  for (i = 0; i < blen; i ++) btmp[i] = b->indices[j++];
  ring_mul_cfsub(r, a, btmp, alen, blen);
  
  // reduce the coefficients of r modulo 2048
  for (i = 0; i < alen-7; i ++) r[i] &= 0x07FF;
}


void test_ring_mul_11(void)
{
  int i, N = 11, alen = 18;    // our implementation requires alen = N+7
  // int blen = 6, rlen = 16;  // rlen must be >= N and a multiple of eight
  int bp1len = 3, bn1len = 3;  // number of +1 and -1 coefficients in array b
  // A is the public key, a polynomial of degree N-1 with coefficients in the
  // range [0, p-1]. However, our implementation requires the array A to have
  // N+7 elements, whereby A[N] = A[0], A[N+1] = A[1], ..., A[N+6] = A[6].
  UINT16 a[18] = { 8, 25, 22, 20, 12, 24, 15, 19, 12, 19, 16, 8, 25, 22, 20,\
                   12, 24, 15 };
  // B is a random polynomial that is sparse; in our example the coefficients
  // B[2], B[3], B[4] are +1, while the coefficients B[0], B[5], B[7] are -1
  UINT16 b[6] = { 2, 3, 4, 0, 5, 7 };
  // C is the message, a polynomial of degree N-1 with coeffs in { -1, 0, 1 }
  UINT16 c[11] = { -1, 0, 0, 1, -1, 0, 0, 0, -1, 1, 1 };
  UINT16 r[16];
  
  for (i = 0; i < N; i ++) r[i] = 0;
  ring_mul_cfadd(r, a, b, alen, bp1len);
  ring_mul_cfsub(r, a, &(b[bp1len]), alen, bn1len);
  for (i = 0; i < N; i ++) r[i] = (r[i] + c[i]) & 0x1F;
  
  printf("r = { ");
  for (i = 0; i < N-1; i ++) printf("%i, ", r[i]);
  printf("%i }\n", r[N-1]);
}


void test_ring_mul_401(void)
{
  int i, N = 401, alen = 408;  // our implementation requires alen = N+7
  int rlen = 408;              // rlen must be >= N and a multiple of eight
  UINT16 a401[408] = { A401COEFFS };  // A401COEFFS is defined in testvec.h
  UINT16 b401[44] = { B401COEFFS };   // B401COEFFS is defined in testvec.h
  // The polynomial b is a sparse polynomial in "product form," which means it
  // is given as b = (b1*b2 + b3).  When N = 401, b1 and b2 have 16 non-zero
  // coefficients (namely eight +1 and eight -1 coefficients), while b3 has 12
  // non-zero coefficients, half of which are +1 and the other half are -1.
  SPARSE_POLY b = { &(b401[0]), 16, 16, 12 };
  UINT16 r[rlen];
  
  // our implementation requires the array A to have a length of N+7 elements,
  // whereby A[N] = A[0], A[N+1] = A[1], ..., and A[N+6] = A[6].
  for (i = 0; i < 7; i ++) a401[(alen-7)+i] = a401[i];  
  ring_mul_sparse(r, a401, &b, alen);
  
  printf("r = { ");
  for (i = 0; i < N-1; i ++) printf("%03x, ", r[i]);
  printf("%03x }\n", r[N-1]);
}
