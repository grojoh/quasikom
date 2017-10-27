///////////////////////////////////////////////////////////////////////////////
// ring_arith.h: Polynomial arithmetic in NTRU ring on 8-bit AVR processors. //
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


#ifndef _RING_ARITH_H
#define _RING_ARITH_H

#include "typedefs.h"

// struct for sparse polynomial in product form (i.e. p = p1*p2 + p3)

typedef struct sparse_polynomial {
  UINT16 *indices;  // indices of non-zero coeffs (for all three polynomials)
  UINT16 p1i_len;   // number of +1 or -1 coefficients in polynomial p1
  UINT16 p2i_len;   // number of +1 or -1 coefficients in polynomial p2
  UINT16 p3i_len;   // number of +1 or -1 coefficients in polynomial p3
} SPARSE_POLY;

// function prototypes

void ring_mul_cfadd_c99(UINT16 *r, const UINT16 *a, UINT16 *b, int alen,
                        int blen);
void ring_mul_cfsub_c99(UINT16 *r, const UINT16 *a, UINT16 *b, int alen,
                        int blen);
void test_ring_mul_11(void);
void test_ring_mul_401(void);

#endif
