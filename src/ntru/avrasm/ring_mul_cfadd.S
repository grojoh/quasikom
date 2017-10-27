///////////////////////////////////////////////////////////////////////////////
// ring_mul_cfadd.S: Coefficient addition for ring multiplication on AVR.    //
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


// Function prototype:
// -------------------
// void ring_mul_cfadd(UINT16 *r, const UINT16 *a, UINT16 *b, int alen, 
//                     int blen);
// 
// Description:
// ------------
// 
// Operands:
// ---------
// 
// Version history:
// ----------------



#include "macros.s"


// define register names

#define BLEN R16       // length of array B
#define INN_STOP R17   // inner-loop stopper
#define LOOP_CTR R20   // loop-counter for outer loop: (N+7)>>3
#define ZERO R21       // ZERO is always 0

// the file "macro.s" contains definitions for the following register names:
// TWONL (R18): lower byte of 16-bit integer 2*N
// TWONH (R19): higher byte of 16-bit integer 2*N
// ADR_ANL (R22): lo-byte of address of coefficient a[N] (resp. a[N-1])
// ADR_ANH (R23): hi-byte of address of coefficient a[N] (resp. a[N-1])


.global ring_mul_cfadd
.func ring_mul_cfadd
ring_mul_cfadd:
    
    // push registers on stack
    
    PUSH_ALL_REGS
    
    // initialize pointers and variables
    
    MOVW ZL, R24        // Z contains address of LSB of array R
    MOVW XL, R22        // X contains address of LSB of array A
    MOVW YL, R20        // Y contains address of LSB of array B
    
    LSL  BLEN           // double BLEN (contains number of bytes of array B)
    MOV  INN_STOP, BLEN // copy 2blen to register INN_STOP
    ADD  INN_STOP, YL   // innr loop stops if Y reaches (2blen+1)-th byte of B
    
    MOVW LOOP_CTR, TWONL  // copy 16-bit integer alen to (ZERO:LOOP_CTR) regs
    DIV8 ZERO, LOOP_CTR // shift (ZERO:LOOP_CTR) 3 bits right to get (N+7)>>3
    CLR  ZERO           // clear ZERO register
    
    SUBI TWONL, 7       // alen is N+7, so we subtract 7 from alen to get N
    SBC  TWONH, ZERO    // propagate carry
    ADD  TWONL, TWONL   // double lo-byte of N to get 2*N
    ADC  TWONH, TWONH   // double hi-byte of N to get 2*N
    
    ADD  ADR_ANL, TWONL // ADR_ANL contains lo-byte of 16-bit address of A[N]
    ADC  ADR_ANH, TWONH // ADR_ANH contains hi-byte of 16-bit address of A[N]
    
    // Array B contains the indices j of the coefficients B[j] of polynomial
    // b(X) that are +1.  To get the result r(X) = r(X) + a(X)*b(X) mod X^N-1,
    // we have to calculate for each coefficient R[k] of r(X) the sum of all
    // coefficient products of the form A[i]*B[j] for which i+j is congruent
    // to k mod N.  Taking the least-significant coefficient R[0] as example,
    // we have to sum up all coefficients A[N-j], except when j = 0 we have to
    // use A[0] instead of A[N].  The following loop calculates for each index
    // j in array B the address of the corresponding coefficient A[N-j] and
    // stores it in array B (i.e. the index j is replaced by the address of
    // A[N-j]).  However, when array B contains index j = 0, we store the
    // address of A[0] instead of the address of A[N].
    
    // START OF FIRST LOOP
    
OUT_LOOP_1ST:
    CALC_COEFF_ADDR     // replace indices j by addresses of coeffs A[N-j]
    CPSE INN_STOP, YL   // check if Y reached the (2blen+1)-th byte of array B
    RJMP OUT_LOOP_1ST   // if not then jump back to the start
    
    // END OF FIRST LOOP
    
    SUB  YL, BLEN       // restore original value of Y pointer
    SBC  YH, ZERO       // propagate carry
    
    // in the second loop we use the address of A[N-1] instead of A[N]
    
    SUBI ADR_ANL, 2     // ADR_ANL contains now lo-byte of address of A[N-1]
    SBC  ADR_ANH, ZERO  // ADR_ANH contains now hi-byte of address of A[N-1]
    
    // Since the coefficients of polynomial b(X) are only 0 or 1, the
    // polynomial multiplication r(X) = r(X) + a(X)*b(X) mod X^N - 1 boils
    // down to the addition of coefficients, which is done in the following
    // nested loop.  In each iteration of the outer loop, we load eight
    // coefficients R[k] from r(X) and add the corresponding coefficients from
    // a(X), starting with the least significant coefficient R[0].  For R[0],
    // we just have to add up all the coefficients A[N-j] for which we have
    // already computed the addresses in the first loop above; these addresses
    // are stored in array B.  However, we do this via an "operand-scanning"
    // approach, i.e. in the first iteration of the inner loop, we add A[N-j]
    // to R[0], A[N-j+1] to R[1], and so forth, until we finally add A[N-j+7]
    // to R[7].  We access array A through the 16-bit X pointer, i.e. at the
    // beginning of the inner loop, we load the current element of array B to
    // the (XH:XL) registers.  The coefficients A[N-j], A[N-j+1], .., A[N-j+7]
    // can be loaded very efficiently from array A thanks to the automatic
    // post-increment addressing mode of AVR.  At the end of the inner loop,
    // we write the address contained in the (XH:XL) register pair back to
    // array B from where we loaded it.  However, since X got incremented by
    // 2 with every loading of a coefficient, it may happen that X exceeds the
    // address of A[N-1], in which case we have to subtract 2*N from X so that
    // X points to an element of array A between A[0] and A[N-1].
    
    // START OF SECOND LOOP 
    
OUT_LOOP_2ND:
    
    LOAD_EIGHT_COEFFS   // load 8 coefficients from array R via Z pointer
    
INN_LOOP_2ND:           // start of inner loop    
    ADD_EIGHT_COEFFS    // load 8 coeffs from A (via X) and add them to 8 sums
    STORE_COEFF_ADDR    // correct address in X if it is > address of A[N-1]
    CPSE INN_STOP, YL   // check if Y reached the (2blen+1)-th byte of array B
    RJMP INN_LOOP_2ND   // if not then jump back to the start
    
    SUB  YL, BLEN       // restore original value of Y pointer
    SBC  YH, ZERO       // propagate carry
    
    STORE_EIGHT_COEFFS  // store 8 coefficients to array R via Z pointer
    
    DEC  LOOP_CTR       // decrement loop-counter by 1
    CPSE LOOP_CTR, ZERO // check whether loop-counter is 0
    RJMP OUT_LOOP_2ND   // if not then jump back to the start
    
    // END OF SECOND LOOP
    
    // pop registers from stack
    
    POP_ALL_REGS
    CLR  R1
    
    // that's all folks :-)
    
    RET
    
.end func
