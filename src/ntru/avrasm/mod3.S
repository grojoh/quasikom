///////////////////////////////////////////////////////////////////////////////
// mod3.S: Reduction of an unsigned 16-bit integer modulo 3 on 8-bit AVR.    //
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
// UINT16 int16_mod3(UINT16 a);
// 
// Description:
// ------------
// 
// Operands:
// ---------
// 
// Version history:
// ----------------


// define register names

#define HIBYTE R25     // upper byte of 16-bit UINT to be reduced mod 3
#define LOBYTE R24     // upper byte of 16-bit UINT to be reduced mod 3
#define MASK R23       // used to mask out upper nibble or upper 6 bits
#define ZERO R22       // ZERO is always 0


.global int16_mod3
.func int16_mod3
int16_mod3:
    
    // initialize variables
    CLR  ZERO
    
    // first step: reduction modulo 85*3 = 255 = 2^8 - 1
    
    ADD  LOBYTE, HIBYTE // 
    ADC  LOBYTE, ZERO   // 
    
    // second step: reduction modulo 5*3 = 15 = 2^4 - 1
    
    LDI  MASK, 0xF      // 
    MOV  HIBYTE, LOBYTE // 
    SWAP HIBYTE         // swap the 4-bit nibbles of HIBYTE
    AND  LOBYTE, MASK   // 
    AND  HIBYTE, MASK   // 
    ADD  LOBYTE, HIBYTE // 
    MOV  HIBYTE, LOBYTE // 
    SWAP HIBYTE         // swap the 4-bit nibbles of HIBYTE
    AND  LOBYTE, MASK   // 
    AND  HIBYTE, MASK   // 
    ADD  LOBYTE, HIBYTE // 
    
    // third step: reduction modulo 3 = 2^2 - 1
    
    LDI  MASK, 0x3      // 
    MOV  HIBYTE, LOBYTE // 
    LSR  HIBYTE         // 
    LSR  HIBYTE         // 
    AND  LOBYTE, MASK   // 
    ADD  LOBYTE, HIBYTE // 
    MOV  HIBYTE, LOBYTE // 
    LSR  HIBYTE         // 
    LSR  HIBYTE         // 
    AND  LOBYTE, MASK   // 
    ADD  LOBYTE, HIBYTE // 
    
    // final subtraction of 3, followed by addition of 3 if difference < 0
    
    SUB  LOBYTE, MASK   // 
    SBC  ZERO, ZERO     // 
    AND  MASK, ZERO     // 
    ADD  LOBYTE, MASK   // 
    
    // pop registers from stack
    
    CLR  HIBYTE
    CLR  R1
    
    // that's all folks :-)
    
    RET
    
.end func
