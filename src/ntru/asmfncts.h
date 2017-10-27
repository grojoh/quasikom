///////////////////////////////////////////////////////////////////////////////
// asmfncts.h: Prototypes of functions implemented in Assembly language.     //
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


#ifndef _ASMFNCTS_H
#define _ASMFNCTS_H

#include "typedefs.h"

// prototypes of Assembler functions

extern void ring_mul_cfadd(UINT16 *r, const UINT16 *a, UINT16 *b, int alen, 
                           int blen);
extern void ring_mul_cfsub(UINT16 *r, const UINT16 *a, UINT16 *b, int alen,
                           int blen);
extern UINT16 int16_mod3(UINT16 a);

#endif
