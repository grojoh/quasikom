///////////////////////////////////////////////////////////////////////////////
// macros.S: Macros for Multiplication ("Convolution") in NTRU Ring on AVR.  //
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


// Version history:
// ----------------
// 1.0.0: first public release; implementation as described in XXXX


#include "avr/io.h"


/////////////////////////////////////////////////////
// definitions to give registers a meaningful name //
/////////////////////////////////////////////////////

// registers for eight coefficient sums

#define SUM0L R0
#define SUM0H R1
#define SUM1L R2
#define SUM1H R3
#define SUM2L R4
#define SUM2H R5
#define SUM3L R6
#define SUM3H R7
#define SUM4L R8
#define SUM4H R9
#define SUM5L R10
#define SUM5H R11
#define SUM6L R12
#define SUM6H R13
#define SUM7L R14
#define SUM7H R15

#define MASKL R14      // lower byte of a 16-bit mask
#define MASKH R15      // lower byte of a 16-bit mask

#define TWONL R18      // lower byte of 16-bit integer 2*N
#define TWONH R19      // higher byte of 16-bit integer 2*N

#define ADR_ANL R22    // lo-byte of address of coefficient a[N] (resp a[N-1])
#define ADR_ANH R23    // hi-byte of address of coefficient a[N] (resp a[N-1])

#define COEFL R24      // lower byte of a 16-bit coefficient
#define COEFH R25      // higher byte of a 16-bit coefficient

#define TMPL R24       // lo-byte of temporary 16-bit int (shared with COEFL)
#define TMPH R25       // hi-byte of temporary 16-bit int (shared with COEFH)


// macro to emulate an "add immediate" instruction

.macro ADDI reg, imm
    SUBI \reg, -(\imm)
.endm

// macro to emulate an "add with carry immediate" instruction

.macro ADCI reg, imm
    SBCI \reg, -(\imm)
.endm

// macro to emulate a "division by 8" instruction for 16-bit integer

.macro DIV8 hib, lob
    LSR  \hib
    ROR  \lob
    LSR  \hib
    ROR  \lob
    LSR  \hib
    ROR  \lob
.endm


//////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////
////////// MACROS FOR REVERSE-PRODUCT SCANNING (RPS) MULTIPLICATION //////////
//////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////


.macro CALC_COEFF_ADDR     // 23 CYCLES
    LD   COEFL, Y       // load lower byte of 16-bit coeff from B via Y ptr
    LDD  COEFH, Y+1     // load higher byte of 16-bit coeff from B via Y ptr
    ADD  COEFL, COEFL   // 
    ADC  COEFH, COEFH   // 
    CLR  MASKL          // clear MASKL register
    COM  COEFL          // calculate 1's complement of COEFL (bitwise inverse)
    COM  COEFH          // calculate 1's complement of COEFH (bitwise inverse)
    ADIW COEFL, 1       // calculate 2's complement of (COEFH:COEFL)
    SBC  MASKL, MASKL   // MASKL is either 255 (if coeff was 0) or 0 otherwise
    MOV  MASKH, MASKL   // MASKH is either 255 (if coeff was 0) or 0 otherwise
    ADD  COEFL, ADR_ANL // 
    ADC  COEFH, ADR_ANH // 
    AND  MASKL, TWONL   // 
    AND  MASKH, TWONH   // 
    SUB  COEFL, MASKL   // 
    SBC  COEFH, MASKH   // 
    ST   Y+, COEFL      // 
    ST   Y+, COEFH      // 
.endm


.macro LOAD_EIGHT_COEFFS    // 32 CYCLES
    LD   SUM0L, Z
    LDD  SUM0H, Z+1
    LDD  SUM1L, Z+2
    LDD  SUM1H, Z+3
    LDD  SUM2L, Z+4
    LDD  SUM2H, Z+5
    LDD  SUM3L, Z+6
    LDD  SUM3H, Z+7
    LDD  SUM4L, Z+8
    LDD  SUM4H, Z+9
    LDD  SUM5L, Z+10
    LDD  SUM5H, Z+11
    LDD  SUM6L, Z+12
    LDD  SUM6H, Z+13
    LDD  SUM7L, Z+14
    LDD  SUM7H, Z+15
.endm


.macro ADD_EIGHT_COEFFS    // 52 CYCLES
    LD   XL, Y          // load lo-byte of 16-bit coeff addr from B via Y ptr
    LDD  XH, Y+1        // load hi-byte of 16-bit coeff addr from B via Y ptr
    LD   COEFL, X+      // load lower byte of 16-bit coeff from A via X ptr
    LD   COEFH, X+      // load higher byte of 16-bit coeff from A via X ptr
    ADD  SUM0L, COEFL   // add lower byte of coeff to lower byte of sum0
    ADC  SUM0H, COEFH   // add higher byte of coeff to higher byte of sum0
    LD   COEFL, X+      // load lower byte of 16-bit coeff from A via X ptr
    LD   COEFH, X+      // load higher byte of 16-bit coeff from A via X ptr
    ADD  SUM1L, COEFL   // add lower byte of coeff to lower byte of sum1
    ADC  SUM1H, COEFH   // add higher byte of coeff to higher byte of sum1
    LD   COEFL, X+      // load lower byte of 16-bit coeff from A via X ptr
    LD   COEFH, X+      // load higher byte of 16-bit coeff from A via X ptr
    ADD  SUM2L, COEFL   // add lower byte of coeff to lower byte of sum2
    ADC  SUM2H, COEFH   // add higher byte of coeff to higher byte of sum2
    LD   COEFL, X+      // load lower byte of 16-bit coeff from A via X ptr
    LD   COEFH, X+      // load higher byte of 16-bit coeff from A via X ptr
    ADD  SUM3L, COEFL   // add lower byte of coeff to lower byte of sum3
    ADC  SUM3H, COEFH   // add higher byte of coeff to higher byte of sum3
    LD   COEFL, X+      // load lower byte of 16-bit coeff from A via X ptr
    LD   COEFH, X+      // load higher byte of 16-bit coeff from A via X ptr
    ADD  SUM4L, COEFL   // add lower byte of coeff to lower byte of sum4
    ADC  SUM4H, COEFH   // add higher byte of coeff to higher byte of sum4
    LD   COEFL, X+      // load lower byte of 16-bit coeff from A via X ptr
    LD   COEFH, X+      // load higher byte of 16-bit coeff from A via X ptr
    ADD  SUM5L, COEFL   // add lower byte of coeff to lower byte of sum5
    ADC  SUM5H, COEFH   // add higher byte of coeff to higher byte of sum5
    LD   COEFL, X+      // load lower byte of 16-bit coeff from A via X ptr
    LD   COEFH, X+      // load higher byte of 16-bit coeff from A via X ptr
    ADD  SUM6L, COEFL   // add lower byte of coeff to lower byte of sum6
    ADC  SUM6H, COEFH   // add higher byte of coeff to higher byte of sum6
    LD   COEFL, X+      // load lower byte of 16-bit coeff from A via X ptr
    LD   COEFH, X+      // load higher byte of 16-bit coeff from A via X ptr
    ADD  SUM7L, COEFL   // add lower byte of coeff to lower byte of sum7
    ADC  SUM7H, COEFH   // add higher byte of coeff to higher byte of sum7
.endm


.macro SUB_EIGHT_COEFFS    // 52 CYCLES
    LD   XL, Y          // load lo-byte of 16-bit coeff addr from B via Y ptr
    LDD  XH, Y+1        // load hi-byte of 16-bit coeff addr from B via Y ptr
    LD   COEFL, X+      // load lower byte of 16-bit coeff from A via X ptr
    LD   COEFH, X+      // load higher byte of 16-bit coeff from A via X ptr
    SUB  SUM0L, COEFL   // subtract lower byte of coeff to lower byte of sum0
    SBC  SUM0H, COEFH   // subtract higher byte of coeff to higher byte of sum0
    LD   COEFL, X+      // load lower byte of 16-bit coeff from A via X ptr
    LD   COEFH, X+      // load higher byte of 16-bit coeff from A via X ptr
    SUB  SUM1L, COEFL   // subtract lower byte of coeff to lower byte of sum1
    SBC  SUM1H, COEFH   // subtract higher byte of coeff to higher byte of sum1
    LD   COEFL, X+      // load lower byte of 16-bit coeff from A via X ptr
    LD   COEFH, X+      // load higher byte of 16-bit coeff from A via X ptr
    SUB  SUM2L, COEFL   // subtract lower byte of coeff to lower byte of sum2
    SBC  SUM2H, COEFH   // subtract higher byte of coeff to higher byte of sum2
    LD   COEFL, X+      // load lower byte of 16-bit coeff from A via X ptr
    LD   COEFH, X+      // load higher byte of 16-bit coeff from A via X ptr
    SUB  SUM3L, COEFL   // subtract lower byte of coeff to lower byte of sum3
    SBC  SUM3H, COEFH   // subtract higher byte of coeff to higher byte of sum3
    LD   COEFL, X+      // load lower byte of 16-bit coeff from A via X ptr
    LD   COEFH, X+      // load higher byte of 16-bit coeff from A via X ptr
    SUB  SUM4L, COEFL   // subtract lower byte of coeff to lower byte of sum4
    SBC  SUM4H, COEFH   // subtract higher byte of coeff to higher byte of sum4
    LD   COEFL, X+      // load lower byte of 16-bit coeff from A via X ptr
    LD   COEFH, X+      // load higher byte of 16-bit coeff from A via X ptr
    SUB  SUM5L, COEFL   // subtract lower byte of coeff to lower byte of sum5
    SBC  SUM5H, COEFH   // subtract higher byte of coeff to higher byte of sum5
    LD   COEFL, X+      // load lower byte of 16-bit coeff from A via X ptr
    LD   COEFH, X+      // load higher byte of 16-bit coeff from A via X ptr
    SUB  SUM6L, COEFL   // subtract lower byte of coeff to lower byte of sum6
    SBC  SUM6H, COEFH   // subtract higher byte of coeff to higher byte of sum6
    LD   COEFL, X+      // load lower byte of 16-bit coeff from A via X ptr
    LD   COEFH, X+      // load higher byte of 16-bit coeff from A via X ptr
    SUB  SUM7L, COEFL   // subtract lower byte of coeff to lower byte of sum7
    SBC  SUM7H, COEFH   // add higher byte of coeff to higher byte of sum7
.endm


.macro STORE_COEFF_ADDR    // 14 CYCLES
    MOVW TMPL, ADR_ANL  // copy 16-bit address of A[N-1] to TMP register pair
    SUB  TMPL, XL       // subtract lo-byte of X (curr coeff addr) from TMPL
    SBC  TMPH, XH       // subtract hi-byte of X (curr coeff addr) from TMPH
    CLR  TMPL           // clear TMPL reg (this does not affect carry flag!)
    SBC  TMPL, TMPL     // TMPL is either 255 (if X > address of A[N-1]) or 0
    MOV  TMPH, TMPL     // TMPH is either 255 (if X > address of A[N-1]) or 0
    AND  TMPL, TWONL    // TMPL is either lo-byte of 2N (X > addr A[N-1]) or 0
    AND  TMPH, TWONH    // TMPL is either hi-byte of 2N (X > addr A[N-1]) or 0
    SUB  XL, TMPL       // subtract 2N from X (only if X > address of A[N-1])
    SBC  XH, TMPH       // subtract 2N from X (only if X > address of A[N-1])
    ST   Y+, XL         // store lo-byte of coeff address in array B via Y ptr
    ST   Y+, XH         // store hi-byte of coeff address in array B via Y ptr
.endm


.macro STORE_EIGHT_COEFFS    // 32 CYCLES
    ST   Z+, SUM0L
    ST   Z+, SUM0H
    ST   Z+, SUM1L
    ST   Z+, SUM1H
    ST   Z+, SUM2L
    ST   Z+, SUM2H
    ST   Z+, SUM3L
    ST   Z+, SUM3H
    ST   Z+, SUM4L
    ST   Z+, SUM4H
    ST   Z+, SUM5L
    ST   Z+, SUM5H
    ST   Z+, SUM6L
    ST   Z+, SUM6H
    ST   Z+, SUM7L
    ST   Z+, SUM7H
.endm



//////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////
//////////////////////// OTHER MACROS FOR GENERAL USE ////////////////////////
//////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////


.macro PUSH_ALL_REGS    // 36 CYCLES
    PUSH R2
    PUSH R3
    PUSH R4
    PUSH R5
    PUSH R6
    PUSH R7
    PUSH R8
    PUSH R9
    PUSH R10
    PUSH R11
    PUSH R12
    PUSH R13
    PUSH R14
    PUSH R15
    PUSH R16
    PUSH R17
    PUSH R28
    PUSH R29
.endm


.macro POP_ALL_REGS     // 36 CYCLES
    POP  R29
    POP  R28
    POP  R17
    POP  R16
    POP  R15
    POP  R14
    POP  R13
    POP  R12
    POP  R11
    POP  R10
    POP  R9
    POP  R8
    POP  R7
    POP  R6
    POP  R5
    POP  R4
    POP  R3
    POP  R2
.endm
