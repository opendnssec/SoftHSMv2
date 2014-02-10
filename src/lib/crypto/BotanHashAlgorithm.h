/*
 * Copyright (c) .SE (The Internet Infrastructure Foundation)
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
 BotanHashAlgorithm.h

 Base class for Botan hash algorithm classes
 *****************************************************************************/

#ifndef _SOFTHSM_V2_BOTANHASHALGORITHM_H
#define _SOFTHSM_V2_BOTANHASHALGORITHM_H

#include "config.h"
#include "HashAlgorithm.h"
#include <botan/hash.h>

class BotanHashAlgorithm : public HashAlgorithm
{
public:
	// Base constructor
	BotanHashAlgorithm();

	// Destructor
	virtual ~BotanHashAlgorithm();

	// Hashing functions
	virtual bool hashInit();
	virtual bool hashUpdate(const ByteString& data);
	virtual bool hashFinal(ByteString& hashedData);

	virtual int getHashSize() = 0;
protected:
	virtual Botan::HashFunction* getHash() const = 0;

private:
	// Current hashing context
	Botan::HashFunction *hash;
};

#endif // !_SOFTHSM_V2_BOTANHASHALGORITHM_H

