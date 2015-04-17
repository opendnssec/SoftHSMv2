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
 RSAParameters.h

 RSA parameters (only used for key generation)
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "RSAParameters.h"
#include <string.h>

// The type
/*static*/ const char* RSAParameters::type = "Generic RSA parameters";

// Set the public exponent
void RSAParameters::setE(const ByteString& inE)
{
	e = inE;
}

// Set the bit length
void RSAParameters::setBitLength(const size_t inBitLen)
{
	bitLen = inBitLen;
}

// Get the public exponent
const ByteString& RSAParameters::getE() const
{
	return e;
}

// Get the bit length
size_t RSAParameters::getBitLength() const
{
	return bitLen;
}

// Are the parameters of the given type?
bool RSAParameters::areOfType(const char* inType)
{
	return (strcmp(type, inType) == 0);
}

// Serialisation
ByteString RSAParameters::serialise() const
{
	ByteString len(bitLen);

	return e.serialise() + len.serialise();
}

bool RSAParameters::deserialise(ByteString& serialised)
{
	ByteString dE = ByteString::chainDeserialise(serialised);
	ByteString dLen = ByteString::chainDeserialise(serialised);

	if ((dE.size() == 0) ||
	    (dLen.size() == 0))
        {
		return false;
	}

	setE(dE);
	setBitLength(dLen.long_val());

        return true;
}
