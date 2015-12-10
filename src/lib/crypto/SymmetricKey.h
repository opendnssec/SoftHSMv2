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
 SymmetricKey.h

 Base class for symmetric key classes
 *****************************************************************************/

#ifndef _SOFTHSM_V2_SYMMETRICKEY_H
#define _SOFTHSM_V2_SYMMETRICKEY_H

#include "config.h"
#include "ByteString.h"
#include "Serialisable.h"

class SymmetricKey : public Serialisable
{
public:
	// Base constructors
	SymmetricKey(size_t inBitLen = 0);

	SymmetricKey(const SymmetricKey& in);

	// Destructor
	virtual ~SymmetricKey() { }

	// Set the key
	virtual bool setKeyBits(const ByteString& keybits);

	// Get the key
	virtual const ByteString& getKeyBits() const;

	// Get the key check value
	virtual ByteString getKeyCheckValue() const;

	// Serialisation
	virtual ByteString serialise() const;

	// Set the bit length
	virtual void setBitLen(const size_t inBitLen);

	// Retrieve the bit length
	virtual size_t getBitLen() const;

protected:
	// The key
	ByteString keyData;

	// The key length in bits
	size_t bitLen;
};

#endif // !_SOFTHSM_V2_SYMMETRICKEY_H

