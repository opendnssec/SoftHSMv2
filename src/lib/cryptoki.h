/*
 * Copyright (c) 2010 SURFnet bv
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*****************************************************************************
 cryptoki.h

 This include file turns on export of functions by the SoftHSM v2 library by
 setting the #define symbol CRYPTOKI_EXPORTS before the main PKCS #11 header
 file is included. Include this header file in alle SoftHSM v2 code that
 links into a PKCS #11 library; currently that will only by softhsm.cpp
 *****************************************************************************/

#ifndef _SOFTHSM_V2_CRYPTOKI_H
#define _SOFTHSM_V2_CRYPTOKI_H

#ifndef CRYPTOKI_EXPORTS
#define CRYPTOKI_EXPORTS
#endif // !CRYPTOKI_EXPORTS

#ifndef CRYPTOKI_COMPAT
#define CRYPTOKI_COMPAT
#endif // !CRYPTOKI_COMPAT

#include "pkcs11.h"

#endif // !_SOFTHSM_V2_CRYPTOKI_H

