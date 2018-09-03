///////////////////////////////////////////////////////////////////////////////
// config.h: A header file to make a number of basic cinfiguration settings. //
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


#ifndef _CONFIG_H
#define _CONFIG_H

#ifdef __AVR__
// To acticate Assembler optimizations
#define AVRSHA_USE_ASM
#endif

#endif  /* _CONFIG_H */
