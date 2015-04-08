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
 RSAPublicKey.cpp

 RSA public key class
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "RSAPublicKey.h"
#include <string.h>

// Set the type
/*static*/ const char* RSAPublicKey::type = "Abstract RSA public key";

// Check if the key is of the given type
bool RSAPublicKey::isOfType(const char* inType)
{
	return !strcmp(type, inType);
}

// Get the bit length
unsigned long RSAPublicKey::getBitLength() const
{
	return getN().bits();
}

// Get the output length
unsigned long RSAPublicKey::getOutputLength() const
{
	// Also handle odd number of bits (bits % 8 != 0)
	return (getBitLength() + 7) / 8;
}

// Setters for the RSA public key components
void RSAPublicKey::setN(const ByteString& inN)
{
	n = inN;
}

void RSAPublicKey::setE(const ByteString& inE)
{
	e = inE;
}

// Getters for the RSA public key components
const ByteString& RSAPublicKey::getN() const
{
	return n;
}

const ByteString& RSAPublicKey::getE() const
{
	return e;
}

// Serialisation
ByteString RSAPublicKey::serialise() const
{
	return n.serialise() +
	       e.serialise();
}

bool RSAPublicKey::deserialise(ByteString& serialised)
{
	ByteString dN = ByteString::chainDeserialise(serialised);
	ByteString dE = ByteString::chainDeserialise(serialised);

	if ((dN.size() == 0) ||
	    (dE.size() == 0))
	{
		return false;
	}

	setN(dN);
	setE(dE);

	return true;
}

