///////////////////////////////////////////////////////////////////////////////
// ntru_demo.c: Demo program for NTRU encryption/decryption on 8-bit AVR.    //
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



#include "asmfncts.h"
#include "debug.h"
#include "ring_arith.h"
// #include "ntru_demo.h"


static FILE mystdout = FDEV_SETUP_STREAM(uart_putch, NULL, _FDEV_SETUP_WRITE);


void testmod3(void)
{
  UINT16 i = 0, err = 0, r, x;
  
  do
  {
    r = i%3;
    x = int16_mod3(i);
    if (r != x) err ++;
    // printf("i = %i, r = %i, x = %i\n", i, r, x);
    i ++;
  } while (i != 0);
  
  printf("errors: %i\n", err);
}


int main(void)
{
  init_uart();
  stdout = &mystdout;
  
  test_ring_mul_11();
  // test_ring_mul_401();
  
  testmod3();
  
  return 0;
}
