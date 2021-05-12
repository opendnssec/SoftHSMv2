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
 OSSLPBKDF2.h

 OpenSSL pbkdf2 algorithm implementation
 *****************************************************************************/

#ifndef _SOFTHSM_V2_OSSLPBKDF2_H
#define _SOFTHSM_V2_OSSLPBKDF2_H

#include "config.h"
#include "PBKDF2Algorithm.h"
#include <openssl/evp.h>

class OSSLPBKDF2 : public PBKDF2Algorithm
{
public:
	// Destructor
	virtual ~OSSLPBKDF2() { }

	// Key factory
	virtual unsigned long getMinKeySize();
	virtual unsigned long getMaxKeySize();
	virtual bool generateKey(SymmetricKey **ppSymmetricKey, PBKDF2Algo::Type algo, const ByteString& passwd, const ByteString& salt, int iterations, int keyLen);

private:
};

#endif // !_SOFTHSM_V2_OSSLPBKDF2_H

