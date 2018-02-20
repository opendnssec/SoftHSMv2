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
 MacAlgorithm.h

 Base class for MAC algorithm classes
 *****************************************************************************/

#ifndef _SOFTHSM_V2_MACALGORITHM_H
#define _SOFTHSM_V2_MACALGORITHM_H

#include <string>
#include "config.h"
#include "SymmetricKey.h"
#include "RNG.h"

struct MacAlgo
{
	enum Type
	{
		Unknown,
		HMAC_MD5,
		HMAC_SHA1,
		HMAC_SHA224,
		HMAC_SHA256,
		HMAC_SHA384,
		HMAC_SHA512,
		HMAC_GOST,
		CMAC_DES,
		CMAC_AES
	};
};

class MacAlgorithm
{
public:
	// Base constructors
	MacAlgorithm();

	// Destructor
	virtual ~MacAlgorithm() { }

	// Signing functions
	virtual bool signInit(const SymmetricKey* key);
	virtual bool signUpdate(const ByteString& dataToSign);
	virtual bool signFinal(ByteString& signature);

	// Verification functions
	virtual bool verifyInit(const SymmetricKey* key);
	virtual bool verifyUpdate(const ByteString& originalData);
	virtual bool verifyFinal(ByteString& signature);

	// Key
	virtual unsigned long getMinKeySize();
	virtual unsigned long getMaxKeySize();
	virtual void recycleKey(SymmetricKey* toRecycle);

	// Return the MAC size
	virtual size_t getMacSize() const = 0;

protected:
	// The current key
	const SymmetricKey* currentKey;

private:
	// The current operation
	enum
	{
		NONE,
		SIGN,
		VERIFY
	} 
	currentOperation;
};

#endif // !_SOFTHSM_V2_MACALGORITHM_H

