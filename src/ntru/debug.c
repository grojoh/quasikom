///////////////////////////////////////////////////////////////////////////////
// debug.c: Simple debug functionality (e.g. debug print-out) for 8-bit AVR. //
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
#include <stdlib.h>
#include <avr\io.h>
#include <string.h>
#include "debug.h"


void init_uart(void)
{
  UCSR0B = _BV(TXEN) | _BV(RXEN);  // tx/rx enable
}


int uart_putch(char c, FILE *stream)
{
  if (c == '\n') uart_putch('\r', stream);
  loop_until_bit_is_set(UCSR0A, UDRE);
  UDR0 = c;
  return 0;
}


void print_bytes(const char *c, const UINT8 *a, int len)
{
  int i;
  
  if ((c != NULL) && (strlen(c) > 0)) printf(c);
  for(i = len-1; i >= 0; i --) printf("%02x", a[i]);
  printf("\n");
}


void print_words(const char *c, const UINT32 *a, int len)
{
  int i;

  if ((c != NULL) && (strlen(c) > 0)) printf(c);
  for (i = len-1; i >= 0; i --)
  {  
    printf("%04x", ((UINT16) (a[i]>>16)));
    printf("%04x", ((UINT16) (a[i])));
  }
  printf("\n");
}
