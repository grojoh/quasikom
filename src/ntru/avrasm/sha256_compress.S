///////////////////////////////////////////////////////////////////////////////
// sha256_compress.S: The compression function of SHA256 in AVR Assembler.   //
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


// Device-specific definitions
#include <avr/io.h>


// 32-bit working registers
#define WR0 R0,R1,R2,R3
#define WR1 R4,R5,R6,R7
#define WR2 R8,R9,R10,R11
#define WR3 R12,R13,R14,R15
// #define WR4 R16,R17,R18,R19
// #define WR5 R20,R21,R22,R23

// Other register names
#define TMP R24
#define CNT R25

// 32-bit offset values
#define OF0 0,1,2,3
#define OF1 4,5,6,7
#define OF2 8,9,10,11
#define OF3 12,13,14,15
#define OF4 16,17,18,19
#define OF5 20,21,22,23
#define OF6 24,25,26,27
#define OF7 28,29,30,31


// Start of code section (in program memory space)
.section .text


///////////////////////////////////////////////////////////////////////////////
//////////////////// 64 ROUND CONSTANTS (IN LITTLE ENDIAN) ////////////////////
///////////////////////////////////////////////////////////////////////////////

// .global RCONST
.type RCONST, @object

RCONST:
.word 0x2f98, 0x428a, 0x4491, 0x7137, 0xfbcf, 0xb5c0, 0xdba5, 0xe9b5
.word 0xc25b, 0x3956, 0x11f1, 0x59f1, 0x82a4, 0x923f, 0x5ed5, 0xab1c
.word 0xaa98, 0xd807, 0x5b01, 0x1283, 0x85be, 0x2431, 0x7dc3, 0x550c
.word 0x5d74, 0x72be, 0xb1fe, 0x80de, 0x06a7, 0x9bdc, 0xf174, 0xc19b
.word 0x69c1, 0xe49b, 0x4786, 0xefbe, 0x9dc6, 0x0fc1, 0xa1cc, 0x240c
.word 0x2c6f, 0x2de9, 0x84aa, 0x4a74, 0xa9dc, 0x5cb0, 0x88da, 0x76f9
.word 0x5152, 0x983e, 0xc66d, 0xa831, 0x27c8, 0xb003, 0x7fc7, 0xbf59
.word 0x0bf3, 0xc6e0, 0x9147, 0xd5a7, 0x6351, 0x06ca, 0x2967, 0x1429
.word 0x0a85, 0x27b7, 0x2138, 0x2e1b, 0x6dfc, 0x4d2c, 0x0d13, 0x5338
.word 0x7354, 0x650a, 0x0abb, 0x766a, 0xc92e, 0x81c2, 0x2c85, 0x9272
.word 0xe8a1, 0xa2bf, 0x664b, 0xa81a, 0x8b70, 0xc24b, 0x51a3, 0xc76c
.word 0xe819, 0xd192, 0x0624, 0xd699, 0x3585, 0xf40e, 0xa070, 0x106a
.word 0xc116, 0x19a4, 0x6c08, 0x1e37, 0x774c, 0x2748, 0xbcb5, 0x34b0
.word 0x0cb3, 0x391c, 0xaa4a, 0x4ed8, 0xca4f, 0x5b9c, 0x6ff3, 0x682e
.word 0x82ee, 0x748f, 0x636f, 0x78a5, 0x7814, 0x84c8, 0x0208, 0x8cc7
.word 0xfffa, 0x90be, 0x6ceb, 0xa450, 0xa3f7, 0xbef9, 0x78f2, 0xc671


///////////////////////////////////////////////////////////////////////////////
///////////// MACROS FOR 32-BIT ARITHMETIC AND LOGICAL OPERATIONS /////////////
///////////////////////////////////////////////////////////////////////////////

// Addition of two 32-bit words: A = A + B
.macro ADD32 a0:req, a1:req, a2:req, a3:req, b0:req, b1:req, b2:req,b3:req
    ADD  \a0, \b0
    ADC  \a1, \b1
    ADC  \a2, \b2
    ADC  \a3, \b3
.endm

// Bitwise AND of two 32-bit words: A = A AND B
.macro AND32 a0:req, a1:req, a2:req, a3:req, b0:req, b1:req, b2:req,b3:req
    AND  \a0, \b0
    AND  \a1, \b1
    AND  \a2, \b2
    AND  \a3, \b3
.endm

// Bitwise OR of two 32-bit words: A = A OR B
.macro OR32 a0:req, a1:req, a2:req, a3:req, b0:req, b1:req, b2:req,b3:req
    OR   \a0, \b0
    OR   \a1, \b1
    OR   \a2, \b2
    OR   \a3, \b3
.endm

// Bitwise XOR of two 32-bit words: A = A XOR B
.macro XOR32 a0:req, a1:req, a2:req, a3:req, b0:req, b1:req, b2:req, b3:req
    EOR  \a0, \b0
    EOR  \a1, \b1
    EOR  \a2, \b2
    EOR  \a3, \b3
.endm

// Moving 32-bit word B to 32-bit word A: A = B
.macro MOV32 a0:req, a1:req, a2:req, a3:req, b0:req, b1:req, b2:req, b3:req
    MOVW \a0, \b0
    MOVW \a2, \b2
.endm


///////////////////////////////////////////////////////////////////////////////
///////////////// MACROS FOR 32-BIT LOAD AND STORE OPERATIONS /////////////////
///////////////////////////////////////////////////////////////////////////////

// Load a 32-bit word from X-pointer with auto-increment
.macro LDXI32 a0:req, a1:req, a2:req, a3:req
    LD   \a0, X+
    LD   \a1, X+
    LD   \a2, X+
    LD   \a3, X+
.endm

// Load a 32-bit word from Y-pointer with auto-increment
.macro LDYI32 a0:req, a1:req, a2:req, a3:req
    LD   \a0, Y+
    LD   \a1, Y+
    LD   \a2, Y+
    LD   \a3, Y+
.endm

// Load a 32-bit word from Z-pointer with auto-increment
.macro LDZI32 a0:req, a1:req, a2:req, a3:req
    LD   \a0, Z+
    LD   \a1, Z+
    LD   \a2, Z+
    LD   \a3, Z+
.endm

// Load a 32-bit word from Y-pointer with literal offset
.macro LDYO32 a0:req, a1:req, a2:req, a3:req, b0:req, b1:req, b2:req, b3:req
    LDD  \a0, Y+\b0
    LDD  \a1, Y+\b1
    LDD  \a2, Y+\b2
    LDD  \a3, Y+\b3
.endm

// Load a 32-bit word from Z-pointer with literal offset
.macro LDZO32 a0:req, a1:req, a2:req, a3:req, b0:req, b1:req, b2:req, b3:req
    LDD  \a0, Z+\b0
    LDD  \a1, Z+\b1
    LDD  \a2, Z+\b2
    LDD  \a3, Z+\b3
.endm

// Load a 32-bit word from program memory with auto-increment
// (program memory can only be accessed via the Z-pointer!)
.macro LPMI32 a0:req, a1:req, a2:req, a3:req
    LPM  \a0, Z+
    LPM  \a1, Z+
    LPM  \a2, Z+
    LPM  \a3, Z+
.endm

// Store a 32-bit word to Y-pointer with auto-increment
.macro STYI32 a0:req, a1:req, a2:req, a3:req
    ST   Y+, \a0
    ST   Y+, \a1
    ST   Y+, \a2
    ST   Y+, \a3
.endm

// Store a 32-bit word to Z-pointer with auto-increment
.macro STZI32 a0:req, a1:req, a2:req, a3:req
    ST   Z+, \a0
    ST   Z+, \a1
    ST   Z+, \a2
    ST   Z+, \a3
.endm

// Store a 32-bit word to Y-pointer with literal offset
.macro STYO32 a0:req, a1:req, a2:req, a3:req, b0:req, b1:req, b2:req, b3:req
    STD  Y+\b0, \a0
    STD  Y+\b1, \a1
    STD  Y+\b2, \a2
    STD  Y+\b3, \a3
.endm

// Store a 32-bit word to Z-pointer with literal offset
.macro STZO32 a0:req, a1:req, a2:req, a3:req, b0:req, b1:req, b2:req, b3:req
    STD  Z+\b0, \a0
    STD  Z+\b1, \a1
    STD  Z+\b2, \a2
    STD  Z+\b3, \a3
.endm

// Store a 32-bit word to X-pointer with auto-increment in reverse order
// (this macro can be used to reverse the byte-order of a 32-bit word)
.macro STXR32 a0:req, a1:req, a2:req, a3:req
    ST   X+, \a3
    ST   X+, \a2
    ST   X+, \a1
    ST   X+, \a0
.endm

// Store a 32-bit word to Y-pointer with auto-decrement
.macro STYD32 a0:req, a1:req, a2:req, a3:req
    ST   -Y, \a3
    ST   -Y, \a2
    ST   -Y, \a1
    ST   -Y, \a0
.endm


///////////////////////////////////////////////////////////////////////////////
///////// MACRO FOR SMALL SIGMA ZERO: A = sigma0(B), B GETS DESTROYED /////////
///////////////////////////////////////////////////////////////////////////////

.macro SSZ32 a0:req, a1:req, a2:req, a3:req, b0:req, b1:req, b2:req, b3:req
    // Move 32-bit word B to 32-bit word A
    MOVW \a0, \b0
    MOVW \a2, \b2
    // Rotate 32-bit word B one bit to the left
    // (corrsponds to right-rotation by 7 bits)
    MOV  TMP, \b3
    ROL  TMP
    ROL  \b0
    ROL  \b1
    ROL  \b2
    ROL  \b3
    // Shift and rotate 32-bit word A two bits to the right
    // [a3,a2,a1,a0] contains the shifted 32-bit word A
    // [TMP,a2,a1,a0] contains the rotated 32-bit word A
    MOV  TMP, \a3
    LSR  \a3
    ROR  \a2
    ROR  \a1
    ROR  \a0
    ROR  TMP
    LSR  \a3
    ROR  \a2
    ROR  \a1
    ROR  \a0
    ROR  TMP
    // Xor 32-bit word B with 8-bit-right-rotated A
    EOR  \b0, \a1
    EOR  \b1, \a2
    EOR  \b2, TMP
    EOR  \b3, \a0
    // Shift 32-bit word A one bit to the right
    // (A is then shifted by three bits altogether)
    LSR  \a3
    ROR  \a2
    ROR  \a1
    ROR  \a0
    // Xor 32-bit word A with 8-bit-right-rotated B
    EOR  \a0, \b1
    EOR  \a1, \b2
    EOR  \a2, \b3
    EOR  \a3, \b0
.endm


///////////////////////////////////////////////////////////////////////////////
///////// MACRO FOR SMALL SIGMA ONE: A = sigma1(B), B GETS DESTROYED //////////
///////////////////////////////////////////////////////////////////////////////

.macro SSO32 a0:req, a1:req, a2:req, a3:req, b0:req, b1:req, b2:req, b3:req
    // Shift and rotate 32-bit word B one bit to the right
    // [TMP,b2,b1,b0] contains the shifted 32-bit word B
    // [b3,b2,b1,b0] contains the rotated 32-bit word B
    MOV  TMP, \b3
    LSR  TMP
    ROR  \b2
    ROR  \b1
    ROR  \b0
    ROR  \b3
    // Initialize 32-bit word A with 16-bit-right-rotated B
    MOVW \a2, \b0
    MOVW \a0, \b2
    // Shift and rotate 32-bit word B one bit to the right
    // (B is then shifted/rotated by two bits altogether)
    LSR  TMP
    ROR  \b2
    ROR  \b1
    ROR  \b0
    ROR  \b3
    // Xor 32-bit word A with 8-bit-right-shifted B
    EOR  \a0, \b1
    EOR  \a1, \b2
    EOR  \a2, TMP
    // Rotate 32-bit word B one bit to the right
    // (B is then rotated by three bits altogether)
    LSR  TMP
    ROR  \b2
    ROR  \b1
    ROR  \b0
    ROR  \b3
    // Xor 32-bit word A with 16-bit-right-rotated B
    EOR  \a0, \b2
    EOR  \a1, \b3
    EOR  \a2, \b0
    EOR  \a3, \b1
.endm


///////////////////////////////////////////////////////////////////////////////
////////// MACRO FOR BIG SIGMA ZERO: A = Sigma0(B), B GETS DESTROYED //////////
///////////////////////////////////////////////////////////////////////////////

.macro BSZ32 a0:req, a1:req, a2:req, a3:req, b0:req, b1:req, b2:req, b3:req
    // Rotate 32-bit word B two bits to the right
    MOV  TMP, \b0
    ROR  TMP
    ROR  \b3
    ROR  \b2
    ROR  \b1
    ROR  \b0
    ROR  TMP
    ROR  \b3
    ROR  \b2
    ROR  \b1
    ROR  \b0
    // Move 32-bit word B to 32-bit word A
    MOVW \a0, \b0
    MOVW \a2, \b2
    // Rotate 32-bit word B three bits to the right
    // (B is then rotated by five bits altogether)
    ROR  TMP
    ROR  \b3
    ROR  \b2
    ROR  \b1
    ROR  \b0
    ROR  TMP
    ROR  \b3
    ROR  \b2
    ROR  \b1
    ROR  \b0
    ROR  TMP
    ROR  \b3
    ROR  \b2
    ROR  \b1
    ROR  \b0
    // Xor 32-bit word A with 8-bit-right-rotated B
    EOR  \a0, \b1
    EOR  \a1, \b2
    EOR  \a2, \b3
    EOR  \a3, \b0
    // Rotate 32-bit word B one bit to the right
    // (B is then rotated by six bits altogether)
    ROR  TMP
    ROR  \b3
    ROR  \b2
    ROR  \b1
    ROR  \b0
    // Xor 32-bit word A with 16-bit-right-rotated B
    EOR  \a0, \b2
    EOR  \a1, \b3
    EOR  \a2, \b0
    EOR  \a3, \b1
.endm


///////////////////////////////////////////////////////////////////////////////
////////// MACRO FOR BIG SIGMA ONE: A = Sigma1(B), B GETS DESTROYED ///////////
///////////////////////////////////////////////////////////////////////////////

.macro BSO32 a0:req, a1:req, a2:req, a3:req, b0:req, b1:req, b2:req, b3:req
    // Rotate 32-bit word B one bit to the right
    MOV  TMP, \b0
    ROR  TMP
    ROR  \b3
    ROR  \b2
    ROR  \b1
    ROR  \b0
    // Move 32-bit word B to 32-bit word A
    MOVW \a0, \b0
    MOVW \a2, \b2
    // Rotate 32-bit word A two bits to the right
    // (A is then rotated by three bits altogether)
    ROR  TMP
    ROR  \a3
    ROR  \a2
    ROR  \a1
    ROR  \a0
    ROR  TMP
    ROR  \a3
    ROR  \a2
    ROR  \a1
    ROR  \a0
    // Xor 32-bit word B with 16-bit-right-rotated A
    EOR  \b0, \a2
    EOR  \b1, \a3
    EOR  \b2, \a0
    EOR  \b3, \a1
    // Rotate 32-bit word A three bits to the right
    // (A is then rotated by six bits altogether)
    ROR  TMP
    ROR  \a3
    ROR  \a2
    ROR  \a1
    ROR  \a0
    ROR  TMP
    ROR  \a3
    ROR  \a2
    ROR  \a1
    ROR  \a0
    ROR  TMP
    ROR  \a3
    ROR  \a2
    ROR  \a1
    ROR  \a0
    // Xor 32-bit word A with 24-bit-right-rotated B
    EOR  \a0, \b3
    EOR  \a1, \b0
    EOR  \a2, \b1
    EOR  \a3, \b2
.endm


///////////////////////////////////////////////////////////////////////////////
// PROLOGUE: PUSH REGS, INITIALIZE X AND Z, AND ALLOCATE TEMP SPACE ON STACK //
///////////////////////////////////////////////////////////////////////////////

.macro CMP_PROLOGUE
    // Push callee-saved registers on the stack
    PUSH R0
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
    // Initialize X-pointer with address of array havl
    // Initialize Z-pointer with address of array m
    MOVW XL, R24
    MOVW ZL, R22
    // Allocate 320 bytes for the arrays s and w on stack
    LDI  CNT, lo8(320)
    LDI  TMP, hi8(320)
    IN   YL, _SFR_IO_ADDR(SPL)
    IN   YH, _SFR_IO_ADDR(SPH)
    SUB  YL, CNT
    SBC  YH, TMP
    IN   TMP, _SFR_IO_ADDR(SREG)
    CLI
    OUT  _SFR_IO_ADDR(SPH), YH
    OUT  _SFR_IO_ADDR(SREG), TMP
    OUT  _SFR_IO_ADDR(SPL), YL
    ADIW YL, 1
    // Y points now to first byte of the allocated space
.endm


///////////////////////////////////////////////////////////////////////////////
///////// EPILOGUE: DEALLOCATE TEMP SPACE FROM STACK AND POP REGISTERS ////////
///////////////////////////////////////////////////////////////////////////////

.macro CMP_EPILOGUE
    // Dellocate 320 bytes from the stack
    LDI  CNT, lo8(320)
    LDI  TMP, hi8(320)
    IN   YL, _SFR_IO_ADDR(SPL)
    IN   YH, _SFR_IO_ADDR(SPH)
    ADD  YL, CNT
    ADC  YH, TMP
    IN   TMP, _SFR_IO_ADDR(SREG)
    CLI
    OUT  _SFR_IO_ADDR(SPH), YH
    OUT  _SFR_IO_ADDR(SREG), TMP
    OUT  _SFR_IO_ADDR(SPL), YL
    // Pop callee-saved registers from the stack
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
    POP  R0
    CLR  R1
.endm


///////////////////////////////////////////////////////////////////////////////
/////////////////// FIRST LOOP OF THE COMPRESSION FUNCTION ////////////////////
///////////////////////////////////////////////////////////////////////////////

// In the first loop of the compression function, the 8 state-words in array s
// (representing the 8 working variables) are initialized with the current hash
// value hval (see sha256.c). Note that we duplicate the state to simplify the
// addressing of words in the 4th loop, i.e. we have 16 words in array s where
// s[0..7] = s[8..15]

.macro CMP_1ST_LOOP
    LDI    CNT, 8           ; set loop-counter CNT to 8
LOOP1:
    LDXI32 WR0              ; WR0 = hval[i]
    STYI32 WR0              ; s[i] = WR0
    STYO32 WR0, OF7         ; s[i+8] = WR0
    DEC    CNT              ; decrement loop-counter CNT
    BRNE   LOOP1            ; if CNT != 0 then jump back to start of loop
    // Set X-pointer to address of hval and push it on stack
    // (we need the address of hval again in the 5th loop!)
    SBIW   XL, 32           ; subtract 32 from X-pointer
    PUSH   XL               ; push lo-byte of X on stack
    PUSH   XH               ; push hi-byte of X on stack
    // Set X-pointer to address of w[0]
    // Array w is located on stack after s
    MOVW   XL, YL           ; set X-pointer to address of s[8]
    ADIW   XL, 32           ; set X-pointer to address of w[0]
    // X contains now the address of w[0]
    // Y contains now the address of s[8]
.endm


///////////////////////////////////////////////////////////////////////////////
/////////////////// SECOND LOOP OF THE COMPRESSION FUNCTION ///////////////////
///////////////////////////////////////////////////////////////////////////////

// In the second loop of the compression function, the byte-order of the 16
// message words is converted from big endian to host byte-order, which is
// little endian for AVR processors. The 16 byte-reversed message words are
// written to array w, which is allocated on the stack (see sha256.c).

.macro CMP_2ND_LOOP
    LDI    CNT, 16          ; set loop-counter CNT to 16
LOOP2:
    LDZI32 WR0              ; WR0 = m[i]
    STXR32 WR0              ; w[i] = WR0 (stored in reverse order!)
    DEC    CNT              ; decrement loop-counter CNT
    BRNE   LOOP2            ; if CNT != 0 then jump back to start of loop
    // Set X back to address of w[0]
    LDI    TMP, 64          ; set TMP to 64
    SUB    XL, TMP          ; subtract 64 from XL
    SBC    XH, CNT          ; propagate carry to XH
.endm


///////////////////////////////////////////////////////////////////////////////
/////////////////// THIRD LOOP OF THE COMPRESSION FUNCTION ////////////////////
///////////////////////////////////////////////////////////////////////////////

// The third loop expands the 16 initial message words (in little endian) to 64
// words (256 bytes), realizing a pre-computed message schedule. This loop is
// iterated 48 times and uses sigma0 and sigma1 (see sha256.c). The C code in
// the sha256_compress() function in sha256.c starts at i = 16 and computes
// w[i] = w[i-16] + w[i-7] + (SSZ32(w[i-15])) + (SSO32(w[i-2])) in each of the
// 48 iterations, whereas the assembler implementation below starts at i = 0
// and computes w[i+16] = w[i] + w[i+9] + (SSZ32(w[i+1])) + (SSO32(w[i+14])).

.macro CMP_3RD_LOOP
    LDI    CNT, 48          ; set loop-counter CNT to 48
    MOVW   ZL, XL           ; we use Z as second pointer
    ADIW   ZL, 36           ; set Z-pointer to address of w[9]
    LDXI32 WR3              ; WR3 = w[i] (via X-pointer)
LOOP3:
    // Load and add w[i], w[i+9]
    LDZI32 WR0              ; WR0 = w[i+9]
    ADD32  WR0, WR3         ; WR0 = w[i+9] + w[i]
    // Load w[i+1] and compute sigma0
    LDXI32 WR1              ; WR1 = w[i+1] (via X-pointer)
    MOV32  WR3, WR1         ; this w[i+1] is the w[i] of the next iteration!
    SSZ32  WR2, WR1         ; WR2 = sigma0(w[i+1])
    ADD32  WR0, WR2         ; WR0 = w[i+9] + w[i] + sigma0
    // Load w[i+14] and compute sigma1
    LDZO32 WR1, OF4         ; WR1 = w[i+14]
    SSO32  WR2, WR1         ; WR2 = sigma1(w[i+14])
    // Compute and store w[i+16]
    ADD32  WR0, WR2         ; WR0 = w[i+9] + w[i] + sigma0 + sigma1
    STZO32 WR0, OF6         ; w[i+16] = WR0
    // Check for loop termination
    DEC    CNT              ; decrement loop-counter CNT
    CLR    TMP              ; set TMP register to 0
    CPSE   TMP, CNT         ; test whether loop-counter CNT is 0
    RJMP   LOOP3            ; if not then jump back to start of loop
    // Set X back to address of w[0]
    LDI    CNT, 196         ; set CNT to 196
    SUB    XL, CNT          ; subtract 196 from XL
    SBC    XH, TMP          ; propagate carry to XH
.endm


///////////////////////////////////////////////////////////////////////////////
/////////////////// FOURTH LOOP OF THE COMPRESSION FUNCTION ///////////////////
///////////////////////////////////////////////////////////////////////////////

// The fourth loop is the most expensive part of the compression function and
// iterated 64 times. In each iteration, the following computations are carried
// out, which involve Sigma0, Sigma1, Majority, and Choice (see sha256.c):
// t1 = s[j+7] + Sigma0(s[j+4]) + Choice(s[j+4], s[j+5], s[j+6]) + k[i] + w[i]
// t2 = Sigma0(s[j]) + Majority(s[j], s[j+1], s[j+2]);
// s[j+3] = s[j+3] + t1;
// s[--j] = t1 + t2;
// if (j == 0) { j = 8; memcpy(&(s[8]), s, 32); }

.macro CMP_4TH_LOOP
    LDI    CNT, 64          ; set loop-counter to 64
    LDI    ZL, lo8(RCONST)  ; set ZL to lo-byte of address of RCONST
    LDI    ZH, hi8(RCONST)  ; set ZH to hi-byte of address of RCONST
LOOP4:
    // Load s[j], s[j+1], s[j+2]
    LDYO32 WR0, OF0         ; WR0 = s[j]
    LDYO32 WR1, OF1         ; WR1 = s[j+1]
    LDYO32 WR2, OF2         ; WR2 = s[j+2]
    // Compute Majority function
    MOV32  WR3, WR0         ; WR3 = s[j]
    OR32   WR3, WR1         ; WR3 = s[j] OR s[j+1]
    AND32  WR2, WR3         ; WR2 = s[j+2] AND (s[j] OR s[j+1])
    AND32  WR1, WR0         ; WR1 = s[j+1] AND s[j]
    OR32   WR2, WR1         ; WR2 = Majority(s[j], s[j+1], s[j+2])
    // Compute Sigma0 function
    BSZ32  WR3, WR0         ; WR3 = Sigma0(s[j])
    ADD32  WR3, WR2         ; WR3 = t2 = Majority + Sigma0
    // Load s[j+4], s[j+5], s[j+6]
    LDYO32 WR0, OF4         ; WR0 = s[j+4]
    LDYO32 WR1, OF5         ; WR1 = s[j+5]
    LDYO32 WR2, OF6         ; WR2 = s[j+6]
    // Compute Choice function
    XOR32  WR1, WR2         ; WR1 = s[j+5] XOR s[j+6]
    AND32  WR1, WR0         ; WR1 = (s[j+5] XOR s[j+6]) AND s[j+4]
    XOR32  WR2, WR1         ; WR2 = Choice(s[j+4], s[j+5], s[j+6])
    // Compute Sigma1 function
    BSO32  WR1, WR0         ; WR1 = Sigma1(s[j+4])
    ADD32  WR1, WR2         ; WR1 = Sigma1 + Choice
    // Load and add k[i], w[i], s[j+7]
    LPMI32 WR2              ; WR2 = k[i] (via Z-pointer)
    ADD32  WR2, WR1         ; WR2 = k[i] + Sigma1 + Choice
    LDXI32 WR1              ; WR1 = w[i] (via X-pointer)
    ADD32  WR1, WR2         ; WR1 = w[i] + k[i] + Sigma1 + Choice
    LDYO32 WR0, OF7         ; WR0 = s[j+7]
    ADD32  WR1, WR0         ; WR1 = t1 = s[j+7] + w[i] + k[i] + Sigma1 + Choice
    // Load, update, and store s[j+3]
    LDYO32 WR0, OF3         ; WR0 = s[j+3]
    ADD32  WR0, WR1         ; WR0 = s[j+3] + t1
    STYO32 WR0, OF3         ; s[j+3] = WR0
    // Compute and store s[j-1]
    ADD32  WR3, WR1         ; WR3 = t2 + t1
    STYD32 WR3              ; s[j-1] = WR3 (Y gets decremented!)
    // Check for duplication of state
    DEC    CNT              ; decrement loop-counter CNT
    MOV    TMP, CNT         ; set TMP register to CNT
    ANDI   TMP, 0xF8        ; mask off the three LSBs of TMP
    CPSE   TMP, CNT         ; test whether CNT is a multiple of 8
    RJMP   LOOP4            ; if not then jump back to start of loop
    // Duplicate the state: s[8..15] = s[0..7]
    LDI    TMP, 8           ; set loop-counter TMP to 8
LOOPD:                      ; we use a loop to reduce code size
    LDYI32 WR0              ; WR0 = s[j]
    STYO32 WR0, OF7         ; s[j+8] = WR0
    DEC    TMP              ; decrement loop-counter TMP
    BRNE   LOOPD            ; if TMP != 0 then jump back to LOOPD
    // Check for loop termination
    CPSE   TMP, CNT         ; test whether loop-counter CNT is 0
    RJMP   LOOP4            ; if not then jump back to start of loop
    // Y-pointer contains now address of s[8]
.endm


///////////////////////////////////////////////////////////////////////////////
/////////////////// FIFTH LOOP OF THE COMPRESSION FUNCTION ////////////////////
///////////////////////////////////////////////////////////////////////////////

// The fifth loop adds the 8 state-words in array s to the current hash value
// in array hval (see sha256.c).

.macro CMP_5TH_LOOP
    // Retrieve the address of array hval from stack
    // (was pushed on the stack in the first loop)
    POP    ZH               ; pop hi-byte of address of hval from stack
    POP    ZL               ; pop lo-byte of address of hval from stack
    LDI    CNT, 8           ; set loop-counter CNT to 8
LOOP5:
    LDZO32 WR0, OF0         ; WR0 = hval[i]
    LDYI32 WR1              ; WR1 = s[i]
    ADD32  WR0, WR1         ; WR0 = WR0 + WR1
    STZI32 WR0              ; hval[i] = WR0
    DEC    CNT              ; decrement loop-counter CNT
    BRNE   LOOP5            ; if CNT != 0 then jump back to start of loop
.endm


///////////////////////////////////////////////////////////////////////////////
//////////////////////////// COMPRESSION FUNCTION /////////////////////////////
///////////////////////////////////////////////////////////////////////////////

// Function prototype:
// -------------------
// void sha256_compress_avr(uint32_t *hval, uint8_t *m);
// 
// Parameters:
// -----------
// hval: address of array containing the current hash value
// m: address of array containing the 64-byte message block
// 
// Return value:
// -------------
// None

.global sha256_compress_avr
.type sha256_compress_avr, @function
.func sha256_compress_avr
sha256_compress_avr:
    CMP_PROLOGUE
    CMP_1ST_LOOP
    CMP_2ND_LOOP
    CMP_3RD_LOOP
    CMP_4TH_LOOP
    CMP_5TH_LOOP
    CMP_EPILOGUE
    RET
.end func
