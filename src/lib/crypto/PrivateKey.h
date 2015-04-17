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
 PrivateKey.h

 Base class for private key classes
 *****************************************************************************/

#ifndef _SOFTHSM_V2_PRIVATEKEY_H
#define _SOFTHSM_V2_PRIVATEKEY_H

#include "config.h"
#include "ByteString.h"
#include "Serialisable.h"
#include <string>

class PrivateKey : public Serialisable
{
public:
	// Base constructors
	PrivateKey() { }

	PrivateKey(const PrivateKey& in);

	// Destructor
	virtual ~PrivateKey() { }

	// Check if the private key is of the given type
	virtual bool isOfType(const char* inType) = 0;

	// Get the bit length
	virtual unsigned long getBitLength() const = 0;

	// Get the output length
	virtual unsigned long getOutputLength() const = 0;

	// Serialisation
	virtual ByteString serialise() const = 0;

	// Encode into PKCS#8 DER
	virtual ByteString PKCS8Encode() = 0;

	// Decode from PKCS#8 BER
	virtual bool PKCS8Decode(const ByteString& ber) = 0;
};

#endif // !_SOFTHSM_V2_PRIVATEKEY_H

